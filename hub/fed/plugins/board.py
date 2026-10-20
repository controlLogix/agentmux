"""Shared board plugin backed by its existing CAS store and local projection."""
from hub.fed.plugin import Param, Plugin, Verb
from hub.fed.board_services import BUCKET, RETRIES, STATUSES, Conflict


class Board(Plugin):
    name = "board"
    tables = [
        "CREATE TABLE IF NOT EXISTS p_board_cards (rid TEXT NOT NULL, key TEXT NOT NULL, repo TEXT, "
        "card TEXT NOT NULL CHECK (json_valid(card)), rev INTEGER NOT NULL, status TEXT, assignee TEXT, "
        "updated_by TEXT, updated_at TEXT, deleted INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (rid, key)) STRICT",
    ]

    def verbs(self):
        P = Param
        return {
            "add": Verb(self.v_add, "put a new card on the shared board of a shared repo", {
                "repo": P(required=True, help="local repo name"), "title": P(), "body": P(positional=True),
                "labels": P("array"), "assign": P(help="peer:<peer>[/<repo>/<role>[/<agent>]]"),
                "from": P(help="copy title and body from a local board card (TM-x)")}),
            "list": Verb(self.v_list, "shared cards (from the local mirror)", {"repo": P(), "status": P()}),
            "show": Verb(self.v_show, "one shared card with comments and history",
                         {"key": P(required=True, positional=True), "repo": P()}),
            "move": Verb(self.v_move, "change a card's status: todo | doing | review | done | blocked",
                         {"key": P(required=True, positional=True), "status": P(required=True), "repo": P()}),
            "assign": Verb(self.v_assign, "assign a card to a person, role or agent anywhere in the circle",
                           {"key": P(required=True, positional=True), "to": P(required=True), "repo": P()}),
            "comment": Verb(self.v_comment, "comment on a card",
                            {"key": P(required=True), "text": P(required=True, positional=True), "repo": P()}),
            "claim": Verb(self.v_claim, "assign the card to yourself and move it to doing, in one CAS",
                          {"key": P(required=True, positional=True), "repo": P()}),
        }


    async def v_add(self, ctx, args, caller):
        return await ctx.board.add(args, caller)

    async def v_move(self, ctx, args, caller):
        return await ctx.board.move(args, caller)

    async def v_assign(self, ctx, args, caller):
        return await ctx.board.assign(args, caller)

    async def v_comment(self, ctx, args, caller):
        return await ctx.board.comment(args, caller)

    async def v_claim(self, ctx, args, caller):
        return await ctx.board.claim(args, caller)

    async def v_list(self, ctx, args, caller):
        return await ctx.projection.list(args, caller)

    async def v_show(self, ctx, args, caller):
        return await ctx.projection.show(args, caller)

    async def on_connect(self, ctx):
        return await ctx.projection.connect()

    async def on_revoke(self, ctx, peer):
        return await ctx.projection.revoke(peer)

    def panel(self, ctx):
        return ctx.projection.panel()


PLUGIN = Board()
