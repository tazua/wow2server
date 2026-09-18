#!/usr/bin/env python3
"""`wow2-discordbot` -- a Discord bot that hands a player a temporary password
for an online profile the server does not know (§73).

    DISCORD_BOT_TOKEN=... wow2-discordbot        # [discord] bot_guild in wow2-server.toml
    wow2-discordbot --dry-run                    # what a player receives, no Discord

A profile that has ever been online sends a sign-in and never a create, and a
sign-in carries a hash of the name and nothing else -- so a server that never
saw the create (a profile from the original servers, or from before a wipe)
holds no credential for it and cannot make one. `/claim NAME` sets a random
password for a name the server does not hold and sends it by DM with the
steps to sign in and change it, pictures included. A name that already has a
password is refused unless the same Discord user set it through this bot;
`/reset NAME @player` (staff) resets any name and sends the kit to that
player; `/account NAME` (staff) says what the store holds. DOCS.md
"Discord" is the operator's side, discord/README.md step 9 the setup.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import enum
import functools
import os
import re
import secrets
import sys
import time
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import authserver as srv                                        # noqa: E402
import serverconfig                                             # noqa: E402
import store                                                    # noqa: E402

GUIDE_DIR = Path(__file__).resolve().parent / "guide"

# Read off a phone screen and typed on the PSP keyboard: no i/l/1, no o/0.
PASSWORD_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"
PASSWORD_LENGTH = 8
# The game's own rule for a profile name (IntroWiz.ProfileInvalid); a name the
# savedata was edited to carry can be shorter, which is what staff's /reset is for.
NAME_RE = re.compile(r"^[A-Za-z0-9]{6,12}$")
LOOSE_NAME_RE = re.compile(r"^[A-Za-z0-9]{1,16}$")
DAY = 86400.0

DEFAULT_TEXT = """\
Here is a temporary password for the online profile **{name}** on **{server}**:

`{password}`

Eight characters, all lower case, no spaces. The name is yours from now on: only \
you (through me) or a server admin can reset it.

**Sign in**
1. Start the game with the profile **{name}** loaded. Another profile active? \
Main Menu → Profile → Manage User Profiles → Change profile.
2. Main Menu → Wireless Multiplayer → Infrastructure mode.
3. When the game asks *Please enter your current password*, type `{password}` \
and press START to finish.

**Change it** (only while signed in; the row is greyed out otherwise)
4. Press ○ until you are back at the Main Menu. That does not sign you out.
5. Profile → Manage User Profiles → Edit profile.
6. Second row, *Change password*. The game asks twice, in this order: first the \
TEMPORARY password `{password}`, then your NEW password (6 to 12 characters). It \
answers *The password for account {name} has been changed*.
7. Optional: *Save password* → On on the same screen, then *Apply Changes and \
Exit*, and the game stops asking for it.

*The online profile name or password is incorrect* means a typo in the \
password, or a profile that is not called exactly {name}. If the game never asks \
for a password and goes straight to that error, it has an old one saved: Edit \
profile → *Save password* → Off, *Apply Changes and Exit*, and try again. Lost \
the new password? `/claim {name}` again. Anything else: {help}.

The pictures, in order: the Infrastructure menu, the password prompt, Edit \
profile, Change password.
"""
TEXT_FIELDS = {"name": "x", "password": "x", "server": "x", "help": "x"}


def log(msg: str) -> None:
    print(f"discord bot: {msg}", flush=True)


def check_text(template: str) -> tuple[str, str | None]:
    """The deployment's kit text if it fills in, else the default and why."""
    if not (template or "").strip():
        return DEFAULT_TEXT, None
    try:
        template.format(**TEXT_FIELDS)
    except (KeyError, IndexError, ValueError) as e:
        return DEFAULT_TEXT, (f"discord.bot_text cannot be filled in ({e!r}; the fields are "
                              f"{', '.join('{' + f + '}' for f in TEXT_FIELDS)}) -- using the default")
    return template, None


def kit_text(name: str, password: str, server: str, help_mention: str,
             template: str = DEFAULT_TEXT) -> str:
    return template.format(name=name, password=password, server=server, help=help_mention)


def guide_files() -> list[Path]:
    """The pictures that go with the kit, in the order the text names them."""
    return sorted(GUIDE_DIR.glob("*.png")) if GUIDE_DIR.is_dir() else []


def name_error(name: str, strict: bool = True) -> str | None:
    """Why `name` cannot be a profile name, or None."""
    if strict and not NAME_RE.match(name):
        return ("a profile name is 6 to 12 characters, letters and digits only "
                "(the game's own rule)")
    if not strict and not LOOSE_NAME_RE.match(name):
        return "letters and digits only, at most 16"
    return None


def new_password(rng=None) -> str:
    rng = rng or secrets.SystemRandom()
    return "".join(rng.choice(PASSWORD_ALPHABET) for _ in range(PASSWORD_LENGTH))


class Outcome(enum.Enum):
    CLAIMED = "claimed"        # the name had no credential; it has one now
    RESET = "reset"            # it had one, and this user may replace it
    TAKEN = "taken"            # it has one that is not this user's to replace
    INVALID = "invalid"
    TOO_MANY = "too many"


@dataclass
class Result:
    outcome: Outcome
    name: str
    password: str | None = None
    detail: str = ""


class Desk:
    """The store's side of the counter: who may have a password for which
    name. Synchronous; the Discord side runs it on one thread, the store's."""

    def __init__(self, claims_per_day: int = 3, rng=None, clock=time.time) -> None:
        self.claims_per_day = int(claims_per_day)
        self.rng = rng
        self.clock = clock
        self.recent: dict[str, list[float]] = {}

    def allowed(self, user_id: str) -> bool:
        if self.claims_per_day <= 0:
            return True
        now = self.clock()
        times = [t for t in self.recent.get(user_id, ()) if now - t < DAY]
        self.recent[user_id] = times
        return len(times) < self.claims_per_day

    def _count(self, user_id: str) -> None:
        self.recent.setdefault(user_id, []).append(self.clock())

    @staticmethod
    def holder(handle: str):
        """(accounts row, discord_claims row) for a handle, either None."""
        conn = store.db()
        acct = conn.execute("SELECT name, pwhash, user_id, last_seen FROM accounts "
                            "WHERE handle = ?", (handle,)).fetchone()
        bound = conn.execute("SELECT user_id, name, at FROM discord_claims WHERE handle = ?",
                             (handle,)).fetchone()
        return acct, bound

    def _issue(self, name: str, user_id: str, kind: Outcome) -> Result:
        password = new_password(self.rng)
        handle = store.account_handle(name)
        with store.tx() as conn:
            srv.set_account_password(name, srv.tiger192(password.encode()))
            conn.execute("INSERT INTO discord_claims (handle, user_id, name, at) "
                         "VALUES (?, ?, ?, ?) ON CONFLICT (handle) DO UPDATE SET "
                         "user_id = excluded.user_id, name = excluded.name, at = excluded.at",
                         (handle, str(user_id), name, store.now_iso()))
            stored = conn.execute("SELECT name FROM accounts WHERE handle = ?",
                                  (handle,)).fetchone()["name"]
        return Result(kind, stored, password)

    def claim(self, name: str, user_id) -> Result:
        """A player asks for a password for a name: theirs if nobody holds it,
        or if they set it through here before."""
        name = name.strip()
        user_id = str(user_id)
        err = name_error(name, strict=True)
        if err:
            return Result(Outcome.INVALID, name, detail=err)
        acct, bound = self.holder(store.account_handle(name))
        if acct and acct["pwhash"]:
            if bound is None or bound["user_id"] != user_id:
                return Result(Outcome.TAKEN, acct["name"],
                              detail="set from a console" if bound is None
                              else "set through the bot by somebody else")
            kind = Outcome.RESET
        else:
            kind = Outcome.CLAIMED
        if not self.allowed(user_id):
            return Result(Outcome.TOO_MANY, name)
        r = self._issue(name, user_id, kind)
        self._count(user_id)
        return r

    def reset(self, name: str, user_id) -> Result:
        """Staff: a new password for any name, bound to the player it is for."""
        name = name.strip()
        err = name_error(name, strict=False)
        if err:
            return Result(Outcome.INVALID, name, detail=err)
        acct, _bound = self.holder(store.account_handle(name))
        kind = Outcome.RESET if acct and acct["pwhash"] else Outcome.CLAIMED
        return self._issue(name, str(user_id), kind)

    def lookup(self, name: str) -> dict:
        name = name.strip()
        handle = store.account_handle(name)
        acct, bound = self.holder(handle)
        return {"name": acct["name"] if acct else name, "handle": handle,
                "registered": bool(acct and acct["pwhash"]),
                "user_id": acct["user_id"] if acct else None,
                "last_seen": acct["last_seen"] if acct else None,
                "claimed_by": bound["user_id"] if bound else None,
                "claimed_at": bound["at"] if bound else None}


# ---------------------------------------------------------------- the handlers
# What each command does, written against a small context so that the suite can
# drive them with no Discord at all; InteractionCtx below is the Discord one.

class Ctx:
    user_id: str = "0"
    user_name: str = "?"
    is_admin: bool = False
    server: str = "the server"
    help_mention: str = "#connection-help"
    template: str = DEFAULT_TEXT

    async def reply(self, text: str, files: list[Path] = ()) -> None:
        """Answer the person who asked; only they see it."""
        raise NotImplementedError

    async def dm(self, user_id: str, text: str, files: list[Path] = ()) -> bool:
        """A direct message; False when their settings refuse it."""
        raise NotImplementedError

    async def run(self, fn, *args):
        """A store call, wherever the store's thread is."""
        return fn(*args)


def _mention(user_id: str) -> str:
    return f"<@{user_id}>"


async def do_claim(desk: Desk, ctx: Ctx, name: str) -> str:
    r = await ctx.run(desk.claim, name, ctx.user_id)
    log(f"/claim {name!r} by {ctx.user_id} ({ctx.user_name}) -> {r.outcome.value}"
        + (f" ({r.detail})" if r.detail else ""))
    if r.outcome in (Outcome.CLAIMED, Outcome.RESET):
        return await _hand_over(ctx, r, to=ctx.user_id)
    if r.outcome is Outcome.TAKEN:
        text = (f"**{r.name}** already has a password on {ctx.server}, and it was not set "
                f"through me by you. If it is your profile and the password is lost, ask in "
                f"{ctx.help_mention}: staff can reset it for you.")
    elif r.outcome is Outcome.TOO_MANY:
        text = (f"That would be more than {desk.claims_per_day} passwords in a day. "
                f"Try again tomorrow, or ask in {ctx.help_mention}.")
    else:
        text = f"`{r.name}` is not a profile name: {r.detail}."
    await ctx.reply(text)
    return text


async def do_reset(desk: Desk, ctx: Ctx, name: str, player_id: str, player_name: str) -> str:
    if not ctx.is_admin:
        text = "Staff only."
        await ctx.reply(text)
        return text
    r = await ctx.run(desk.reset, name, player_id)
    log(f"/reset {name!r} for {player_id} ({player_name}) by {ctx.user_id} ({ctx.user_name}) "
        f"-> {r.outcome.value}" + (f" ({r.detail})" if r.detail else ""))
    if r.outcome is Outcome.INVALID:
        text = f"`{r.name}` cannot be a profile name: {r.detail}."
        await ctx.reply(text)
        return text
    return await _hand_over(ctx, r, to=player_id)


async def do_account(desk: Desk, ctx: Ctx, name: str) -> str:
    if not ctx.is_admin:
        text = "Staff only."
        await ctx.reply(text)
        return text
    d = await ctx.run(desk.lookup, name)
    if d["registered"]:
        text = (f"**{d['name']}**: registered (handle `{d['handle']}`, user id {d['user_id']}, "
                f"last seen {d['last_seen'] or 'never'})")
    else:
        text = f"**{d['name']}**: no password on file (handle `{d['handle']}`)"
    if d["claimed_by"]:
        text += f"; password set through me by {_mention(d['claimed_by'])} at {d['claimed_at']}"
    text += "."
    await ctx.reply(text)
    return text


async def _hand_over(ctx: Ctx, r: Result, to: str) -> str:
    """The kit goes to `to` by DM; when their settings refuse it, whoever asked
    gets it instead, privately, to pass on."""
    kit = kit_text(r.name, r.password, ctx.server, ctx.help_mention, ctx.template)
    files = guide_files()
    if await ctx.dm(to, kit, files):
        text = ("Sent you a DM with the password and the steps." if to == ctx.user_id
                else f"Sent {_mention(to)} a DM with a new password for **{r.name}** and the steps.")
        await ctx.reply(text)
        return text
    who = "you" if to == ctx.user_id else _mention(to)
    text = (f"I could not DM {who} (privacy settings), so here it is; only you can see "
            f"this message.\n\n{kit}")
    await ctx.reply(text, files)
    return text


# ---------------------------------------------------------------- Discord

def invite_url(app_id: int | str) -> str:
    """The setup bot's invite with the scope slash commands need; opening it
    again for a bot already in the server adds the scope and removes nothing."""
    return (f"https://discord.com/oauth2/authorize?client_id={app_id}"
            f"&scope=bot%20applications.commands&permissions=8&integration_type=0")


def run_bot(token: str, guild_id: int, desk: Desk, admin_roles: list[str],
            help_channel: str, template: str) -> int:
    import logging
    import discord
    from discord import app_commands
    globals()["discord"] = discord    # the callbacks' annotations are strings, evaluated in the module's globals

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="store")
    try:
        pool.submit(store.db).result()    # opens the store on its thread; the errors are the CLIs'
    except store.StoreError as e:
        log(f"!! {e}")
        return 1

    intents = discord.Intents.default()
    guild_obj = discord.Object(id=guild_id)
    failed: list[str] = []

    class Bot(discord.Client):
        async def setup_hook(self) -> None:
            tree.copy_global_to(guild=guild_obj)
            try:
                cmds = await tree.sync(guild=guild_obj)
            except discord.Forbidden:
                failed.append("scope")
                log(f"!! the application is in the server without the applications.commands "
                    f"scope, so it may not register slash commands. Open "
                    f"{invite_url(self.application_id)} once, signed in to Discord, pick the "
                    f"server (nothing is removed), and restart")
                await self.close()
                return
            log(f"registered {', '.join('/' + c.name for c in cmds)} in guild {guild_id}")

        async def on_ready(self) -> None:
            g = self.get_guild(guild_id)
            if g is None:
                failed.append("guild")
                log(f"!! the bot is not in guild {guild_id}; check [discord] bot_guild and "
                    f"that the setup bot was added to that server")
                await self.close()
                return
            log(f"online as {self.user} in {g.name!r}; staff = {', '.join(admin_roles)} "
                f"or Manage Server; help -> #{help_channel}")

    client = Bot(intents=intents)
    tree = app_commands.CommandTree(client)

    def attachments(files) -> dict:
        return {"files": [discord.File(p) for p in files]} if files else {}

    def help_mention(g) -> str:
        ch = next((c for c in g.text_channels if c.name == help_channel
                   or c.name.endswith(help_channel)), None)
        return ch.mention if ch else f"#{help_channel}"

    def is_admin(user) -> bool:
        if not isinstance(user, discord.Member):
            return False
        return user.guild_permissions.manage_guild or any(r.name in admin_roles for r in user.roles)

    class InteractionCtx(Ctx):
        def __init__(self, interaction) -> None:
            self.i = interaction
            self.user_id = str(interaction.user.id)
            self.user_name = str(interaction.user)
            self.is_admin = is_admin(interaction.user)
            g = interaction.guild or client.get_guild(guild_id)
            self.server = g.name if g else "the server"
            self.help_mention = help_mention(g) if g else f"#{help_channel}"
            self.template = template

        async def reply(self, text, files=()):
            await self.i.followup.send(text, ephemeral=True, **attachments(files))

        async def dm(self, user_id, text, files=()):
            return await send_dm(user_id, text, files)

        async def run(self, fn, *args):
            return await client.loop.run_in_executor(pool, functools.partial(fn, *args))

    class MessageCtx(InteractionCtx):
        """A DM to the bot: the reply goes back into the same conversation."""
        def __init__(self, message) -> None:
            self.m = message
            self.user_id = str(message.author.id)
            self.user_name = str(message.author)
            self.is_admin = False
            g = client.get_guild(guild_id)
            self.server = g.name if g else "the server"
            self.help_mention = help_mention(g) if g else f"#{help_channel}"
            self.template = template

        async def reply(self, text, files=()):
            await self.m.channel.send(text, **attachments(files))

    async def send_dm(user_id, text, files) -> bool:
        try:
            user = client.get_user(int(user_id)) or await client.fetch_user(int(user_id))
            await user.send(text, **attachments(files))
            return True
        except discord.Forbidden:
            return False
        except discord.HTTPException as e:
            log(f"!! DM to {user_id} failed: {e}")
            return False

    @tree.command(name="claim", description="A temporary password for your online "
                                            "profile, sent to you by DM")
    @app_commands.describe(name="your profile name in the game, exactly as it is spelt")
    async def claim(interaction, name: str):
        await interaction.response.defer(ephemeral=True, thinking=True)
        await do_claim(desk, InteractionCtx(interaction), name)

    @tree.command(name="reset", description="Staff: a new password for any profile, "
                                            "sent to that player by DM")
    @app_commands.describe(name="the profile name", player="who gets the password")
    @app_commands.default_permissions(manage_guild=True)
    async def reset(interaction, name: str, player: discord.User):
        await interaction.response.defer(ephemeral=True, thinking=True)
        await do_reset(desk, InteractionCtx(interaction), name, str(player.id), str(player))

    @tree.command(name="account", description="Staff: what the server holds for a "
                                              "profile name")
    @app_commands.describe(name="the profile name")
    @app_commands.default_permissions(manage_guild=True)
    async def account(interaction, name: str):
        await interaction.response.defer(ephemeral=True, thinking=True)
        await do_account(desk, InteractionCtx(interaction), name)

    @client.event
    async def on_message(message):
        if message.author.bot or message.guild is not None:
            return
        words = message.content.split()
        if len(words) == 1 and LOOSE_NAME_RE.match(words[0]):
            await do_claim(desk, MessageCtx(message), words[0])
        else:
            await message.channel.send("Send me your profile name and nothing else "
                                       "(or use `/claim` in the server) and I answer with "
                                       "a temporary password and the steps.")

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("discord bot: [%(name)s] %(message)s"))
    try:
        client.run(token, log_handler=handler, log_level=logging.WARNING)
    except discord.LoginFailure as e:
        log(f"!! Discord refused the token: {e}")
        return 1
    finally:
        pool.shutdown(wait=False)
    return 1 if failed else 0


# ---------------------------------------------------------------- CLI

def dry_run(template: str) -> int:
    text, bad = check_text(template)
    if bad:
        print(f"!! {bad}")
    print(kit_text("BoggyB", new_password(), "Wormhole", "#connection-help", text))
    files = guide_files()
    print(f"-- {len(files)} picture(s): " + ", ".join(p.name for p in files)
          if files else "-- no pictures (no guide/ directory beside this module)")
    return 0


def cli(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="wow2-discordbot", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true",
                    help="print what a player receives and stop; no Discord, no store")
    args = ap.parse_args(argv)
    template, bad = check_text(serverconfig.DISCORD_BOT_TEXT)
    if bad:
        log(f"!! {bad}")
    if args.dry_run:
        return dry_run(template)
    guild = int(serverconfig.DISCORD_BOT_GUILD or 0)
    if not guild:
        log("off: [discord] bot_guild is not set (Server Settings > Developer Mode, "
            "right-click the server > Copy Server ID)")
        return 0
    token = os.environ.get("DISCORD_BOT_TOKEN", "")
    if not token:
        log("!! DISCORD_BOT_TOKEN is not in the environment (the setup bot's token; "
            "discord/README.md step 2, or /etc/wow2-server.env on a system install)")
        return 1
    if not guide_files():
        log("!! no pictures found beside the module (guide/*.png); the kit goes out as text")
    log(f"guild {guild}, {serverconfig.DISCORD_BOT_CLAIMS_PER_DAY} passwords per person "
        f"per day, store {store.path()}")
    return run_bot(token, guild, Desk(serverconfig.DISCORD_BOT_CLAIMS_PER_DAY),
                   list(serverconfig.DISCORD_BOT_ADMIN_ROLES),
                   serverconfig.DISCORD_BOT_HELP_CHANNEL, template)


if __name__ == "__main__":
    raise SystemExit(cli())
