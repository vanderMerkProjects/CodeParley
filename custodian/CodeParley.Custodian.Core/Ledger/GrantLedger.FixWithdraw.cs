using System.Text.Json.Nodes;
using CodeParley.Custodian.Ipc;
using CodeParley.Custodian.Security;

namespace CodeParley.Custodian.Ledger;

/// <summary>
/// POST-1 Fix Withdraw (contract revision 2): the operator withdraws exactly one confirmed, unconsumed delegated fix, so it
/// can never be applied.
///
/// <para><b>The enforcement is one run-record write.</b> Under the gate the fix goes from <c>confirmed</c> to the terminal
/// <c>withdrawn</c> (with <c>withdrawnAt</c> / <c>withdrawnBy</c>), its proposal is retired and one event is appended, in
/// one atomic <see cref="WriteRun"/>. An application's gated decision checks the status first and refuses
/// <c>CONFIRMATION_WITHDRAWN</c>. Withdrawal and consumption are the two transitions out of <c>confirmed</c>, each one gated
/// write, so exactly one of them happens. The audit line and the content's deletion follow separately; neither is an
/// enforcement step.</para>
///
/// <para><b>Reduce-only.</b> It needs no usable configuration, no readable content and no directory re-check (like a revoke),
/// and it changes nothing but this one operation's fields and the run's log.</para>
///
/// <para><b>Selection.</b> The custodian selects the fix's current confirmation id at prepare and binds it into the intent;
/// a guided selection also names the listed confirmation id, the repository identity and the two digests (all or none).
/// A withdrawal observed at prepare is answered "already withdrawn" (nothing prepared); a prepared commit that finds the
/// fix withdrawn or consumed since refuses and records nothing.</para>
/// </summary>
internal sealed partial class GrantLedger
{
    internal const string FixWithdrawalAction = "fix_withdrawal";
    internal const string FixWithdrawn = "withdrawn";
    internal const string FixWithdrawalFactsSchema = "codeparley.custodian-fix-withdrawal-prepared.v1";

    /// <summary>A guided withdrawal's expected values (all four: the dispatcher refuses fewer).</summary>
    internal sealed record WithdrawalSelection(string RepoKey, string ConfirmationId, string ProposalDigest, string RenderingDigest);

    /// <summary>The run's log has room for one more record and a withdrawal's or decision's write stays within the size cap;
    /// otherwise <c>BUDGET_EXHAUSTED</c> with the one recovery a full log accepts (ending the run).</summary>
    private static void RequireLogRoom(RunRecord run, RunRecord? next, string what)
    {
        string recovery = "end the run instead (`" + OperatorWording.Cli + " runs stop <run> --close --repo <path>`, accepted with a full log): that retires every proposal of the run, a confirmed fix included, so it can never be applied; it also ends the run's other work";
        if (run.Events.Count >= CustodianConstants.MaxRunEvents)
            throw new CustodianRefusal(ErrorCodes.BudgetExhausted, $"the run's log is full ({CustodianConstants.MaxRunEvents} records), so the custodian cannot record {what}; nothing was recorded. Recovery: {recovery}");
        if (next is not null)
        {
            try { RequireProjectionWithinCap(next); }
            catch (CustodianRefusal) { throw new CustodianRefusal(ErrorCodes.BudgetExhausted, $"the run's record is at its size cap, so the custodian cannot record {what}; nothing was recorded. Recovery: {recovery}"); }
        }
    }

    /// <summary>The "state shown" a withdrawal's commit re-derives: the run's end, the fix's status, its confirmation
    /// (identity, consumption, expiry, void, withdrawal), its proposal's digest and retirement and the confirmed rendering.</summary>
    private static string FixWithdrawalStateDigest(RunRecord? run, string operationId)
    {
        RunOperation? op = run?.Operations.FirstOrDefault(o => o.OperationId == operationId && o.Kind == "fix");
        JsonObject? p = op is null ? null : ProposalOf(op);
        JsonObject? c = op?.Outcome?["confirmation"] as JsonObject;
        return Digest.Sha256Hex(Digest.Canonical(new JsonObject
        {
            ["schema"] = "codeparley.custodian-fix-withdrawal-state.v1",
            ["runTerminal"] = run?.IsTerminal, ["status"] = op?.Status,
            ["confirmationId"] = (string?)c?["confirmationId"], ["consumedAt"] = (string?)c?["consumedAt"], ["expiresAt"] = (string?)c?["expiresAt"],
            ["voidedAt"] = (string?)c?["voidedAt"], ["withdrawnAt"] = (string?)c?["withdrawnAt"],
            ["proposalDigest"] = (string?)p?["proposalDigest"], ["retiredAt"] = (string?)p?["retiredAt"], ["renderingDigest"] = (string?)c?["renderingDigest"],
        }));
    }

    /// <summary>Why a fix cannot be withdrawn, by its state (null: it can). <paramref name="sincePrepared"/>: the commit's
    /// wording (the state changed after this withdrawal was prepared, so this commit records nothing).</summary>
    private static CustodianRefusal? NotWithdrawable(RunRecord run, RunOperation op, bool sincePrepared)
    {
        JsonObject? c = op.Outcome?["confirmation"] as JsonObject;
        string id = op.OperationId;
        string? applyStatus = (string?)c?["consumedBy"] is string by ? run.Operations.FirstOrDefault(o => o.OperationId == by)?.Status : null;
        return op.Status switch
        {
            FixWithdrawn => new CustodianRefusal(ErrorCodes.ConfirmationWithdrawn, sincePrepared
                ? $"delegated fix {id} was withdrawn at {(string?)c?["withdrawnAt"]} by another withdrawal since this one was prepared; this commit recorded nothing"
                : $"delegated fix {id} is already withdrawn (at {(string?)c?["withdrawnAt"]}, {(string?)c?["withdrawnBy"]?["assurance"]}); nothing changed"),
            FixConsumed => new CustodianRefusal(ErrorCodes.ConfirmationConsumed,
                $"the confirmation of delegated fix {id} already crossed the consumption boundary: application {(string?)c?["consumedBy"]} began at {(string?)c?["consumedAt"]} ({applyStatus ?? "unknown"}); the withdrawal did nothing. "
                + (applyStatus == RunOperationStatuses.Running
                    ? "It may be writing now; neither a withdrawal nor ending the run undoes an application under way. Inspect it with `" + OperatorWording.Cli + " fix show`; an interrupted one is reconciled with `code-parley fix reconcile`"
                    : applyStatus == Applied
                        ? "Its files stay as they are (a withdrawal never reverts files)"
                        : "It can never be applied again; an interrupted application is reconciled with `code-parley fix reconcile`")),
            FixDeclined => new CustodianRefusal(ErrorCodes.FixDeclined, $"delegated fix {id} was rejected by the owner; it can never be applied; nothing to withdraw"),
            FixConfirmed when run.IsTerminal => new CustodianRefusal(ErrorCodes.RunTerminal, $"the run has ended ({run.Status}); its fixes can no longer be applied; nothing to withdraw"),
            FixConfirmed when c is null || (string?)c["decision"] != "confirm" => new CustodianRefusal(ErrorCodes.FixNotConfirmed, $"delegated fix {id} has no owner confirmation; nothing to withdraw"),
            FixConfirmed => null,
            _ => new CustodianRefusal(ErrorCodes.FixNotConfirmed, $"delegated fix {id} was never confirmed ({op.Status}); nothing to withdraw. A pending proposal is rejected instead (`" + OperatorWording.Cli + " fix review` or `fix reject`)"),
        };
    }

    /// <summary>The run after withdrawing <paramref name="op"/>: the status, the confirmation's withdrawal, the proposal
    /// retired, one event; and the result recorded with it.</summary>
    private static (RunRecord Next, JsonObject Stored) WithdrawnRun(RunRecord run, RunOperation op, DateTime now, string requestId, string? proofDigest)
    {
        var outcome = (JsonObject)op.Outcome!.DeepClone();
        var c = (JsonObject)outcome["confirmation"]!;
        var p = (JsonObject)outcome["proposal"]!;
        c["withdrawnAt"] = Iso(now);
        c["withdrawnBy"] = new JsonObject
        {
            ["role"] = "user", ["channel"] = "custodian_operator", ["assurance"] = Platform.OperatorAssurance, ["proof_digest"] = proofDigest, ["request_id"] = requestId,
        };
        p["retiredAt"] ??= Iso(now);
        p["retiredReason"] = FixWithdrawn;
        RunRecord withOp = run with { Operations = ReplaceOperation(run, op with { Status = FixWithdrawn, Outcome = outcome }) };
        int revision = run.RunRevision + 1;
        var stored = new JsonObject
        {
            ["runId"] = run.RunId, ["kind"] = FixWithdrawalAction, ["runRevision"] = revision, ["status"] = withOp.Status,
            ["operationId"] = op.OperationId, ["operationStatus"] = FixWithdrawn, ["confirmationId"] = c["confirmationId"]?.DeepClone(),
            ["renderingDigest"] = c["renderingDigest"]?.DeepClone(), ["proposalDigest"] = p["proposalDigest"]?.DeepClone(),
            ["withdrawnAt"] = Iso(now), ["assurance"] = Platform.OperatorAssurance,
        };
        var evidence = new RunEvent(run.Events.Count + 1, FixWithdrawalAction, requestId, "operator", null, Digest.Sha256Hex(Digest.Canonical(stored)), run.Status, withOp.Status, Iso(now), (JsonObject)stored.DeepClone());
        return (withOp with { RunRevision = revision, Events = [.. run.Events, evidence] }, stored);
    }

    // ---- operator: prepare a withdrawal ----

    /// <summary><c>prepare_fix_withdrawal</c> (operator surface): prepare the withdrawal of a fix's current confirmation.
    /// The repository is located by <paramref name="repositoryRoot"/> (resolved) or, for a guided selection only, by its
    /// listed identity. Nothing is recorded until <see cref="Commit"/>.</summary>
    internal PreparedAuthorization PrepareFixWithdrawal(string? repositoryRoot, string runId, string operationId, string requestId, WithdrawalSelection? expected)
    {
        ValidateRunId(runId);
        RunFields.RequireToken("operationId", operationId, 64);
        string repoKey;
        string? canonical = null;
        if (repositoryRoot is not null)
        {
            RepoIdentity id = RepoIdentities.Resolve(repositoryRoot);
            if (expected is not null && id.Key != expected.RepoKey)
                throw new CustodianRefusal(ErrorCodes.SelectionStale, $"the repository path now resolves to identity {id.Key}, not the identity that was selected ({expected.RepoKey}); nothing was prepared — list again");
            (repoKey, canonical) = (id.Key, id.CanonicalPath);
        }
        else repoKey = expected?.RepoKey ?? throw new CustodianRefusal(ErrorCodes.MalformedRequest, "a withdrawal names the repository's path, or (a guided selection) all four expected values");
        lock (EnterGate())
        {
            RunRecord run = ReadRun(repoKey, runId) ?? throw new CustodianRefusal(ErrorCodes.RunNotOpen, "the custodian holds no record of this run");
            RunOperation op = FixOperationOf(run, operationId);
            if (NotWithdrawable(run, op, sincePrepared: false) is { } refusal) throw refusal;
            JsonObject c = (JsonObject)op.Outcome!["confirmation"]!;
            JsonObject p = ProposalOf(op)!;
            string confirmationId = (string)c["confirmationId"]!;
            string? rendering = (string?)c["renderingDigest"], proposalDigest = (string?)p["proposalDigest"];
            if (expected is not null)
            {
                if (confirmationId != expected.ConfirmationId)
                    throw new CustodianRefusal(ErrorCodes.SelectionStale, $"delegated fix {operationId} now carries confirmation {confirmationId}, not the one that was listed ({expected.ConfirmationId}); nothing was prepared — list again");
                if (proposalDigest != expected.ProposalDigest || rendering != expected.RenderingDigest)
                    throw new CustodianRefusal(ErrorCodes.SelectionStale, $"delegated fix {operationId}'s confirmed proposal or rendering is not the one that was listed; nothing was prepared — list again");
            }
            DateTime now = _clock();
            RequireLogRoom(run, WithdrawnRun(run, op, now, requestId, null).Next, "a withdrawal");
            var args = new JsonObject
            {
                ["repositoryRoot"] = canonical, ["repoKey"] = repoKey, ["runId"] = runId, ["operationId"] = operationId,
                ["confirmationId"] = confirmationId, ["proposalDigest"] = proposalDigest, ["renderingDigest"] = rendering,
            };
            var changed = (p["changes"] as JsonArray ?? []).OfType<JsonObject>().Select(x => FixRendering.Escape((string?)x["path"] ?? "")).ToList();
            bool lapsed = c["voidedAt"] is not null || ParseTime((string)c["expiresAt"]!) <= now || p["retiredAt"] is not null;
            string statement =
                $"Withdraw the confirmation of delegated fix {operationId} of run {runId}:\n"
                + $"  repository   {(canonical is null ? "identity " + repoKey : FixRendering.Escape(canonical) + " (identity " + repoKey + ")")}\n"
                + $"  confirmation {confirmationId}, recorded {(string?)c["recordedAt"]} ({(string?)c["recordedBy"]?["assurance"]}), expires {(string?)c["expiresAt"]}\n"
                + $"  rendering    sha256 {rendering}\n"
                + $"  changes      {changed.Count} path(s): {string.Join(", ", changed.Take(MaxListedPaths))}{(changed.Count > MaxListedPaths ? ", …" : "")}\n"
                + (lapsed ? "  It is already not applicable (expired or voided); the withdrawal makes that permanent.\n" : "")
                + "\nThe withdrawal is permanent: this confirmation can never be applied, also after a restart, a new configuration or a resumed session.\n"
                + "Nothing was applied by it, and no file is changed. The run, the repository's configuration and every other fix stay as they are.\n"
                + "A fix applied earlier is not reverted.";
            var facts = new JsonObject
            {
                ["schema"] = FixWithdrawalFactsSchema, ["repoKey"] = repoKey, ["repositoryRoot"] = canonical, ["runId"] = runId, ["operationId"] = operationId,
                ["confirmationId"] = confirmationId, ["proposalDigest"] = proposalDigest, ["renderingDigest"] = rendering,
                ["confirmationExpiresAt"] = (string?)c["expiresAt"], ["alreadyNotApplicable"] = lapsed,
            };
            return PrepareIntent(FixWithdrawalAction, args, FixWithdrawalStateDigest(run, operationId), requestId, statement) with { Facts = facts };
        }
    }

    /// <summary>The commit of a withdrawal, in the commit's hold: the state re-derived; a fix withdrawn, consumed, ended or
    /// otherwise changed since the prepare is refused with what happened (this commit records nothing).</summary>
    private void RequireFreshFixWithdrawal(JsonObject args, string recordedState)
    {
        RunRecord run = ReadRun((string)args["repoKey"]!, (string)args["runId"]!) ?? throw new CustodianRefusal(ErrorCodes.RunNotOpen, "the custodian holds no record of this run");
        RunOperation op = FixOperationOf(run, (string)args["operationId"]!);
        if (FixWithdrawalStateDigest(run, op.OperationId) == recordedState) return;
        if (NotWithdrawable(run, op, sincePrepared: true) is { } refusal) throw refusal;
        throw new CustodianRefusal(ErrorCodes.SelectionStale, $"delegated fix {op.OperationId}'s confirmation changed since this withdrawal was prepared; this commit recorded nothing — prepare it again");
    }

    /// <summary>Record the withdrawal (single hold, after the freshness checks): one run write, then the audit line; the
    /// retired content is deleted after the gate.</summary>
    private JsonObject ApplyFixWithdrawal(JsonObject args, string requestId, string digest, string? proof)
    {
        RunRecord run = ReadRun((string)args["repoKey"]!, (string)args["runId"]!)!;
        RunOperation op = FixOperationOf(run, (string)args["operationId"]!);
        if ((string?)op.Outcome?["confirmation"]?["confirmationId"] != (string?)args["confirmationId"])
            throw new CustodianRefusal(ErrorCodes.SelectionStale, "the fix carries another confirmation than the one this withdrawal was prepared for; this commit recorded nothing");
        (RunRecord next, JsonObject stored) = WithdrawnRun(run, op, _clock(), requestId, proof ?? digest);
        RequireLogRoom(run, next, "a withdrawal");
        Hold(HoldPoints.FixWithdrawalWrite);
        WriteRun(next); // the enforcement: persisted BEFORE the audit line and the cleanup
        Audit($"fix_withdrawal committed runId={run.RunId} operationId={op.OperationId} confirmationId={(string?)args["confirmationId"]} rendering={((string?)args["renderingDigest"])?[..16]} requestId={requestId} assurance={Platform.OperatorAssurance}");
        _retiredProposals.Enqueue(ProposalPath(run.RepoKey, run.RunId, op.OperationId));
        return stored;
    }
}
