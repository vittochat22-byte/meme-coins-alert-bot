"""
Meme Coin Alert Bot
Fonti: DexScreener, Rugcheck, Reddit, Nitter/X
"""

import asyncio
import aiohttp
import json
import os
import time
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("bot.log")],
)
log = logging.getLogger("meme-bot")

# ─────────────────────────────────────────────
# CONFIGURAZIONE FILTRI
# ─────────────────────────────────────────────

@dataclass
class Config:
    # --- Sicurezza (hard filters) ---
    # Alzato: i top 10 holder spesso superano il 20% nei token nuovi legittimi
    max_top10_holders_pct: float = 40.0      # % max dei top 10 holders
    # Alzato: alcuni dev tengono fino al 10% legittimamente
    max_dev_wallet_pct: float = 10.0         # % max del dev wallet
    # Disabilitato: molti token nuovi non hanno ancora revocato il mint
    require_mint_revoked: bool = False       # mint authority revocata
    # Mantenuto: freeze authority è un rischio reale (può congelare i wallet)
    require_freeze_revoked: bool = True      # freeze authority revocata
    # Disabilitato: la LP locked è rara nei primissimi minuti/ore
    require_lp_locked: bool = False          # liquidity locked
    # Mantenuto: honeypot check è il filtro di sicurezza più importante
    check_honeypot: bool = True              # simula buy/sell

    # --- Qualità ---
    # Abbassato: token nuovi partono spesso con liquidità più bassa
    min_liquidity_usd: float = 5_000
    # Alzato: non limitare token che stanno crescendo bene
    max_liquidity_usd: float = 1_000_000
    # Abbassato: mcap basso è normale per token nuovi
    min_mcap_usd: float = 20_000
    # Alzato: più spazio per token in crescita
    max_mcap_usd: float = 2_000_000
    # Abbassato: catturiamo token più freschi
    min_age_minutes: int = 15
    # Alzato: includiamo token fino a 12 ore
    max_age_minutes: int = 720
    # Abbassato: 20 holders in poche ore è già un segnale positivo
    min_holders: int = 20

    # --- Momentum ---
    # Abbassato: anche volumi più contenuti possono indicare interesse reale
    min_volume_5m_usd: float = 2_000
    # Abbassato: meno tx richieste per i token più nuovi
    min_tx_5m: int = 10
    # Abbassato: ratio 1.2x è già bullish
    min_buy_sell_ratio: float = 1.2
    # Abbassato: anche movimenti più contenuti sono validi
    min_price_change_5m_pct: float = 2.0
    # Alzato: lasciamo spazio a pump più forti prima di escluderli
    max_price_change_5m_pct: float = 50.0

    # --- Scoring (pesi) ---
    # Ridotto il peso sicurezza per compensare i filtri hard allentati
    weight_security: int = 35
    weight_liquidity: int = 15
    weight_vol_mcap: int = 20
    weight_buy_sell: int = 20
    weight_social: int = 10
    # Abbassato leggermente: con filtri più larghi il punteggio medio scende
    min_score_to_alert: int = 60

    # --- Runtime ---
    scan_interval_seconds: int = 40
    alert_cooldown_seconds: int = 3600       # non ri-alertare lo stesso token per 1h

    # --- API Keys ---
    # Rugcheck non richiede API key (endpoint pubblico)
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""


# ─────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────

@dataclass
class TokenData:
    address: str
    symbol: str
    name: str
    chain: str = "solana"
    price_usd: float = 0.0
    liquidity_usd: float = 0.0
    market_cap_usd: float = 0.0
    volume_5m_usd: float = 0.0
    volume_1h_usd: float = 0.0
    tx_5m: int = 0
    buys_5m: int = 0
    sells_5m: int = 0
    price_change_5m_pct: float = 0.0
    holders: int = 0
    top10_holders_pct: float = 0.0
    dev_wallet_pct: float = 0.0
    mint_revoked: bool = False
    freeze_revoked: bool = False
    lp_locked: bool = False
    is_honeypot: bool = False
    social_mention: bool = False
    created_at: Optional[int] = None         # unix timestamp
    age_minutes: int = 0
    pair_address: str = ""
    dex_url: str = ""

    @property
    def buy_sell_ratio(self) -> float:
        if self.sells_5m == 0:
            return float(self.buys_5m) if self.buys_5m > 0 else 0.0
        return self.buys_5m / self.sells_5m

    @property
    def vol_mcap_ratio(self) -> float:
        if self.market_cap_usd == 0:
            return 0.0
        return self.volume_5m_usd / self.market_cap_usd


@dataclass
class ScoreResult:
    score: int
    passed_hard_filters: bool
    details: dict = field(default_factory=dict)


# ─────────────────────────────────────────────
# SCORING ENGINE
# ─────────────────────────────────────────────

def score_token(token: TokenData, cfg: Config) -> ScoreResult:
    details = {}

    # Hard filter: sicurezza
    sec_ok = (
        token.top10_holders_pct < cfg.max_top10_holders_pct
        and token.dev_wallet_pct < cfg.max_dev_wallet_pct
        and (not cfg.require_mint_revoked or token.mint_revoked)
        and (not cfg.require_freeze_revoked or token.freeze_revoked)
        and (not cfg.require_lp_locked or token.lp_locked)
        and (not cfg.check_honeypot or not token.is_honeypot)
    )
    if not sec_ok:
        return ScoreResult(score=0, passed_hard_filters=False,
                           details={"security": "FAIL"})

    score = cfg.weight_security
    details["security"] = "PASS"

    # Liquidità in range
    liq_ok = cfg.min_liquidity_usd <= token.liquidity_usd <= cfg.max_liquidity_usd
    details["liquidity"] = "PASS" if liq_ok else "FAIL"
    if liq_ok:
        score += cfg.weight_liquidity

    # Volume/MCap ratio > 0.1
    vol_ok = token.vol_mcap_ratio >= 0.1
    details["vol_mcap"] = f"{token.vol_mcap_ratio:.3f} ({'PASS' if vol_ok else 'FAIL'})"
    if vol_ok:
        score += cfg.weight_vol_mcap

    # Buy/Sell ratio
    bs_ok = token.buy_sell_ratio >= cfg.min_buy_sell_ratio
    details["buy_sell"] = f"{token.buy_sell_ratio:.2f}x ({'PASS' if bs_ok else 'FAIL'})"
    if bs_ok:
        score += cfg.weight_buy_sell

    # Social mention
    details["social"] = "PASS" if token.social_mention else "MISS"
    if token.social_mention:
        score += cfg.weight_social

    return ScoreResult(
        score=min(100, score),
        passed_hard_filters=True,
        details=details,
    )


def passes_quality_filters(token: TokenData, cfg: Config) -> tuple[bool, str]:
    if token.liquidity_usd < cfg.min_liquidity_usd:
        return False, f"liquidità troppo bassa: ${token.liquidity_usd:,.0f}"
    if token.liquidity_usd > cfg.max_liquidity_usd:
        return False, f"liquidità troppo alta: ${token.liquidity_usd:,.0f}"
    if token.market_cap_usd < cfg.min_mcap_usd:
        return False, f"mcap troppo basso: ${token.market_cap_usd:,.0f}"
    if token.market_cap_usd > cfg.max_mcap_usd:
        return False, f"mcap troppo alto: ${token.market_cap_usd:,.0f}"
    if token.age_minutes < cfg.min_age_minutes:
        return False, f"token troppo nuovo: {token.age_minutes} min"
    if token.age_minutes > cfg.max_age_minutes:
        return False, f"token troppo vecchio: {token.age_minutes} min"
    if token.holders < cfg.min_holders:
        return False, f"pochi holders: {token.holders}"
    if token.volume_5m_usd < cfg.min_volume_5m_usd:
        return False, f"volume 5m basso: ${token.volume_5m_usd:,.0f}"
    if token.tx_5m < cfg.min_tx_5m:
        return False, f"poche tx 5m: {token.tx_5m}"
    if token.price_change_5m_pct < cfg.min_price_change_5m_pct:
        return False, f"variazione bassa: {token.price_change_5m_pct:.1f}%"
    if token.price_change_5m_pct > cfg.max_price_change_5m_pct:
        return False, f"variazione troppo alta: {token.price_change_5m_pct:.1f}%"
    return True, "ok"


# ─────────────────────────────────────────────
# DATA SOURCES
# ─────────────────────────────────────────────

class DexScreenerSource:
    BASE = "https://api.dexscreener.com"

    async def get_new_pairs(self, session: aiohttp.ClientSession) -> list[dict]:
        """Recupera le pair dei token Solana profilati di recente.

        L'endpoint /latest/dex/pairs/solana (senza pairId) non esiste:
        usiamo /token-profiles/latest/v1 per scoprire nuovi token, poi
        /token-pairs/v1/solana/{address} per ottenere le relative pair.
        """
        profiles_url = f"{self.BASE}/token-profiles/latest/v1"
        try:
            async with session.get(profiles_url, timeout=aiohttp.ClientTimeout(total=10)) as r:
                if r.content_type != "application/json":
                    log.warning(f"DexScreener error: unexpected mimetype {r.content_type}, status {r.status}")
                    return []
                profiles = await r.json()
        except Exception as e:
            log.warning(f"DexScreener profiles error: {e}")
            return []

        if not isinstance(profiles, list):
            return []

        # Filtra solo i profili Solana
        solana_addresses = [
            p["tokenAddress"] for p in profiles
            if p.get("chainId") == "solana" and p.get("tokenAddress")
        ]

        # Recupera le pair per ogni token (in concorrenza limitata)
        semaphore = asyncio.Semaphore(10)

        async def fetch_pairs(address: str) -> list[dict]:
            async with semaphore:
                pairs_url = f"{self.BASE}/token-pairs/v1/solana/{address}"
                try:
                    async with session.get(pairs_url, timeout=aiohttp.ClientTimeout(total=10)) as r:
                        if r.content_type != "application/json":
                            return []
                        data = await r.json()
                        return data if isinstance(data, list) else []
                except Exception as e:
                    log.debug(f"DexScreener pairs error ({address}): {e}")
                    return []

        results = await asyncio.gather(*[fetch_pairs(a) for a in solana_addresses])
        all_pairs = [pair for pairs in results for pair in pairs]
        return all_pairs

    async def get_token(self, session: aiohttp.ClientSession, address: str) -> Optional[dict]:
        url = f"{self.BASE}/tokens/v1/solana/{address}"
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as r:
                if r.content_type != "application/json":
                    log.warning(f"DexScreener token error ({address}): unexpected mimetype {r.content_type}")
                    return None
                data = await r.json()
                return data[0] if isinstance(data, list) and data else None
        except Exception as e:
            log.warning(f"DexScreener token error ({address}): {e}")
            return None

    def parse_pair(self, pair: dict) -> Optional[TokenData]:
        try:
            base = pair.get("baseToken", {})
            info = pair.get("info", {})
            created = pair.get("pairCreatedAt")
            now = int(time.time() * 1000)
            age_min = int((now - created) / 60000) if created else 9999

            volume = pair.get("volume", {})
            txns = pair.get("txns", {})
            txns5 = txns.get("m5", {})
            price_change = pair.get("priceChange", {})
            liquidity = pair.get("liquidity", {})

            return TokenData(
                address=base.get("address", ""),
                symbol=base.get("symbol", ""),
                name=base.get("name", ""),
                chain=pair.get("chainId", "solana"),
                price_usd=float(pair.get("priceUsd", 0) or 0),
                liquidity_usd=float(liquidity.get("usd", 0) or 0),
                market_cap_usd=float(pair.get("marketCap", 0) or 0),
                volume_5m_usd=float(volume.get("m5", 0) or 0),
                volume_1h_usd=float(volume.get("h1", 0) or 0),
                tx_5m=int(txns5.get("buys", 0)) + int(txns5.get("sells", 0)),
                buys_5m=int(txns5.get("buys", 0)),
                sells_5m=int(txns5.get("sells", 0)),
                price_change_5m_pct=float(price_change.get("m5", 0) or 0),
                created_at=created,
                age_minutes=age_min,
                pair_address=pair.get("pairAddress", ""),
                dex_url=pair.get("url", f"https://dexscreener.com/solana/{base.get('address','')}"),
            )
        except Exception as e:
            log.warning(f"Parse pair error: {e}")
            return None


class RugcheckSource:
    """Fonte dati di sicurezza via Rugcheck (https://rugcheck.xyz).
    Endpoint pubblico, nessuna API key necessaria.
    Endpoint: GET https://api.rugcheck.xyz/v1/tokens/{address}/report
    """
    BASE = "https://api.rugcheck.xyz/v1"
    _cache: dict = {}                        # address -> report (TTL-less, session)
    _semaphore: Optional[asyncio.Semaphore] = None   # max 2 chiamate concorrenti
    _MIN_INTERVAL = 0.6                      # secondi minimi tra chiamate successive
    _last_call: float = 0.0

    def _get_semaphore(self) -> asyncio.Semaphore:
        if self._semaphore is None:
            RugcheckSource._semaphore = asyncio.Semaphore(2)
        return self._semaphore

    async def get_report(self, session: aiohttp.ClientSession, address: str) -> Optional[dict]:
        # Cache hit
        if address in self._cache:
            return self._cache[address]

        url = f"{self.BASE}/tokens/{address}/report"
        max_retries = 4

        async with self._get_semaphore():
            # Rate limiting: rispetta un intervallo minimo tra chiamate
            now = time.monotonic()
            wait = self._MIN_INTERVAL - (now - RugcheckSource._last_call)
            if wait > 0:
                await asyncio.sleep(wait)

            for attempt in range(max_retries):
                try:
                    RugcheckSource._last_call = time.monotonic()
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as r:
                        if r.status == 429:
                            retry_after = float(r.headers.get("Retry-After", 2 ** (attempt + 1)))
                            log.debug(f"Rugcheck 429 ({address}), retry in {retry_after:.1f}s (attempt {attempt+1}/{max_retries})")
                            await asyncio.sleep(retry_after)
                            continue
                        if r.status != 200:
                            log.warning(f"Rugcheck error ({address}): HTTP {r.status}")
                            return None
                        data = await r.json()
                        self._cache[address] = data
                        return data
                except Exception as e:
                    if attempt < max_retries - 1:
                        await asyncio.sleep(2 ** attempt)
                    else:
                        log.warning(f"Rugcheck error ({address}): {e}")
            return None

    async def enrich_token(self, session: aiohttp.ClientSession, token: TokenData) -> TokenData:
        report = await self.get_report(session, token.address)
        if not report:
            return token

        # Holders: Rugcheck esprime le percentuali (0-100) nel campo "pct"
        top_holders = report.get("topHolders", [])
        if top_holders:
            top10_pct = sum(h.get("pct", 0) for h in top_holders[:10])
            token.top10_holders_pct = min(float(top10_pct), 100.0)
            token.dev_wallet_pct = float(top_holders[0].get("pct", 0))

        # Contatore holders totali
        token_meta = report.get("token", {})
        if token_meta.get("holdersCount"):
            token.holders = int(token_meta["holdersCount"])

        # Mint / Freeze authority: None = revocata
        token.mint_revoked = not report.get("mintAuthority")
        token.freeze_revoked = not report.get("freezeAuthority")

        # LP locked: almeno un market con >= 80% LP locked
        markets = report.get("markets", [])
        token.lp_locked = any(
            m.get("lp", {}).get("lpLockedPct", 0) >= 80
            for m in markets
        )

        # Honeypot: cerca nei rischi segnalati da Rugcheck
        risks = report.get("risks", [])
        token.is_honeypot = any(
            "honeypot" in r.get("name", "").lower() or
            "honeypot" in r.get("description", "").lower()
            for r in risks
            if r.get("level") in ("danger", "warn")
        )

        return token


class SocialSource:
    REDDIT_BASE = "https://www.reddit.com"
    NITTER_BASE = "https://nitter.net"

    async def check_mentions(self, session: aiohttp.ClientSession, symbol: str, address: str) -> bool:
        ticker = symbol.lstrip("$").lower()
        reddit_found = await self._check_reddit(session, ticker)
        if reddit_found:
            return True
        x_found = await self._check_nitter(session, ticker)
        if x_found:
            return True
        addr_found = await self._check_reddit(session, address[:8])
        return addr_found

    async def _check_reddit(self, session: aiohttp.ClientSession, query: str) -> bool:
        url = f"{self.REDDIT_BASE}/search.json"
        headers = {"User-Agent": "meme-coin-bot/1.0"}
        try:
            async with session.get(url, params={"q": query, "sort": "new", "limit": 5},
                                   headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=8)) as r:
                data = await r.json()
                posts = data.get("data", {}).get("children", [])
                now = time.time()
                for p in posts:
                    created = p.get("data", {}).get("created_utc", 0)
                    if now - created < 86400:  # ultime 24h
                        return True
                return False
        except Exception as e:
            log.debug(f"Reddit check error ({query}): {e}")
            return False

    async def _check_nitter(self, session: aiohttp.ClientSession, ticker: str) -> bool:
        """Cerca su Nitter (istanza pubblica). Fallback graceful se non disponibile."""
        instances = [
            "https://nitter.net",
            "https://nitter.privacydev.net",
        ]
        for base in instances:
            try:
                url = f"{base}/search"
                async with session.get(url, params={"q": f"${ticker}", "f": "tweets"},
                                       timeout=aiohttp.ClientTimeout(total=8)) as r:
                    text = await r.text()
                    if "tweet-date" in text and ticker.lower() in text.lower():
                        return True
            except Exception:
                continue
        return False


# ─────────────────────────────────────────────
# ALERT DISPATCHER
# ─────────────────────────────────────────────

class AlertDispatcher:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._sent: dict[str, float] = {}  # address -> last alert timestamp

    def is_cooldown(self, address: str) -> bool:
        last = self._sent.get(address, 0)
        return time.time() - last < self.cfg.alert_cooldown_seconds

    def mark_sent(self, address: str):
        self._sent[address] = time.time()

    def format_alert(self, token: TokenData, result: ScoreResult) -> str:
        axiom_url = f"https://axiom.trade/t/{token.address}"
        dex_url = token.dex_url or f"https://dexscreener.com/solana/{token.address}"
        checks = " | ".join(f"{k}: {v}" for k, v in result.details.items())
        lines = [
            f"🚨 ALERT: {token.symbol} ({token.name})",
            f"Score: {result.score}/100",
            f"",
            f"💧 Liquidità: ${token.liquidity_usd:,.0f}",
            f"📊 MCap: ${token.market_cap_usd:,.0f}",
            f"📈 Vol 5m: ${token.volume_5m_usd:,.0f}",
            f"🔄 Buy/Sell: {token.buy_sell_ratio:.2f}x",
            f"⚡ Δ5m: +{token.price_change_5m_pct:.1f}%",
            f"👥 Holders: {token.holders}",
            f"⏱ Età: {token.age_minutes} min",
            f"",
            f"Checks: {checks}",
            f"",
            f"🔗 Axiom: {axiom_url}",
            f"📉 DexScreener: {dex_url}",
            f"📍 {token.address}",
        ]
        return "\n".join(lines)

    async def send_telegram(self, session: aiohttp.ClientSession, text: str):
        if not self.cfg.telegram_bot_token or not self.cfg.telegram_chat_id:
            return
        url = f"https://api.telegram.org/bot{self.cfg.telegram_bot_token}/sendMessage"
        payload = {
            "chat_id": self.cfg.telegram_chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        try:
            async with session.post(url, json=payload,
                                    timeout=aiohttp.ClientTimeout(total=10)) as r:
                if r.status != 200:
                    log.warning(f"Telegram error: {await r.text()}")
        except Exception as e:
            log.warning(f"Telegram send error: {e}")

    async def dispatch(self, session: aiohttp.ClientSession, token: TokenData, result: ScoreResult):
        if self.is_cooldown(token.address):
            return
        self.mark_sent(token.address)
        msg = self.format_alert(token, result)
        log.info(f"\n{'='*60}\n{msg}\n{'='*60}")
        await self.send_telegram(session, msg)


# ─────────────────────────────────────────────
# MAIN BOT LOOP
# ─────────────────────────────────────────────

class MemeCoinBot:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.dex = DexScreenerSource()
        self.rugcheck = RugcheckSource()
        self.social = SocialSource()
        self.dispatcher = AlertDispatcher(cfg)
        self._stats = {"scanned": 0, "passed": 0, "alerted": 0, "blocked": 0}

    async def process_token(self, session: aiohttp.ClientSession, raw_pair: dict):
        token = self.dex.parse_pair(raw_pair)
        if not token or not token.address:
            return

        self._stats["scanned"] += 1

        # Arricchisci con dati Rugcheck (holders, mint/freeze, LP, honeypot)
        token = await self.rugcheck.enrich_token(session, token)

        # Controllo filtri di qualità
        ok, reason = passes_quality_filters(token, self.cfg)
        if not ok:
            log.info(f"⛔ Skip {token.symbol}: {reason}")
            self._stats["blocked"] += 1
            return

        # Controllo social
        token.social_mention = await self.social.check_mentions(
            session, token.symbol, token.address
        )

        # Scoring
        result = score_token(token, self.cfg)

        if not result.passed_hard_filters:
            log.info(f"🚫 {token.symbol} BLOCCATO (rug risk) | top10={token.top10_holders_pct:.1f}% dev={token.dev_wallet_pct:.1f}%")
            self._stats["blocked"] += 1
            return

        self._stats["passed"] += 1
        log.info(f"✅ {token.symbol} | score={result.score} | liq=${token.liquidity_usd:,.0f} | bs={token.buy_sell_ratio:.2f}x | age={token.age_minutes}m")

        if result.score >= self.cfg.min_score_to_alert:
            self._stats["alerted"] += 1
            await self.dispatcher.dispatch(session, token, result)

    async def scan_once(self, session: aiohttp.ClientSession):
        log.info("🔍 Avvio scansione nuovi token Solana...")
        pairs = await self.dex.get_new_pairs(session)

        # Filtra solo quelli nell'intervallo di età
        fresh = [
            p for p in pairs
            if p.get("pairCreatedAt") and
            self.cfg.min_age_minutes * 60 * 1000
            <= (int(time.time() * 1000) - p["pairCreatedAt"])
            <= self.cfg.max_age_minutes * 60 * 1000
        ]

        log.info(f"Trovate {len(fresh)} coppie nell'intervallo di età su {len(pairs)} totali")

        # Processa in concorrenza (max 5 per non sovraccaricare le API)
        semaphore = asyncio.Semaphore(5)
        async def bounded(pair):
            async with semaphore:
                await self.process_token(session, pair)

        await asyncio.gather(*[bounded(p) for p in fresh])

        log.info(
            f"📊 Stats: scansionati={self._stats['scanned']} "
            f"passati={self._stats['passed']} "
            f"alert={self._stats['alerted']} "
            f"bloccati={self._stats['blocked']}"
        )

    async def run(self):
        log.info("🚀 Meme Coin Alert Bot avviato")
        log.info(f"Intervallo scansione: {self.cfg.scan_interval_seconds}s")
        log.info(f"Score minimo alert: {self.cfg.min_score_to_alert}/100")

        connector = aiohttp.TCPConnector(limit=20, ttl_dns_cache=300)
        async with aiohttp.ClientSession(connector=connector) as session:
            while True:
                try:
                    await self.scan_once(session)
                except Exception as e:
                    log.error(f"Errore nel ciclo principale: {e}", exc_info=True)
                log.info(f"⏳ Prossima scansione tra {self.cfg.scan_interval_seconds}s")
                await asyncio.sleep(self.cfg.scan_interval_seconds)


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    cfg = Config(
        telegram_bot_token=os.getenv("TELEGRAM_BOT_TOKEN", ""),
        telegram_chat_id=os.getenv("TELEGRAM_CHAT_ID", ""),
        scan_interval_seconds=int(os.getenv("SCAN_INTERVAL", "60")),
        min_score_to_alert=int(os.getenv("MIN_SCORE", "70")),
    )
    asyncio.run(MemeCoinBot(cfg).run())
