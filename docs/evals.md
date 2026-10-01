# Eval tasks

These tasks exist to find out whether an agent can operate a real network with
this tool surface. They test the surface, not the model: a task fails here when
the tools made the right move hard to find, not when the model had a bad day.

Each one is a sentence an operator would actually say. None of them names a
tool, because naming the tool would test nothing — choosing it is the thing
under test.

## What a run produces

Run each task against the configured server through the selected transport, and keep the
tool-call transcript. The transcript is the artifact; the answer is secondary.

**Store the transcript with access controls appropriate to its contents.**
A task can mint working guest passes, and the registry classifies those results
as sensitive. Keep the complete tool response for evaluation and limit who can
read the resulting artifact.

Read each transcript against the task's expected path and record which of these
happened:

- **Wrong tool.** The agent chose a tool that could not answer the question.
- **Guessed parameter.** The agent passed a value the schema rejected, or used
  the wrong parameter name.
- **Extra round trip.** The agent needed an avoidable call, such as a separate
  lookup for an identifier the first tool could have accepted directly.
- **Dead end.** The agent could not complete the task with available tools.
- **Clarified.** The agent asked for a choice only the operator could make.
  This is appropriate when the tools could not supply the answer.
- **Model error.** The agent had the needed tool information and went wrong.
- **Clean.** The agent followed the expected path on the first try.

### Telling a surface defect from a model error

This is the judgement the whole exercise rests on, so it gets a rule rather
than a feel. A non-clean outcome is a **surface defect** when the transcript
shows the agent was misled, and a **model error** when it shows the agent had
what it needed and did not use it. Two questions decide it:

1. **Read the tool list and the schemas as the agent saw them, without knowing
   the answer.** Could a careful reader have found the right move from the
   names, descriptions, and parameter documentation alone? If not — the name
   suggests the wrong thing, the description omits what the parameter accepts,
   the result does not say what it returned — that is the surface. If the
   needed fact was stated plainly and the agent went past it, that is the
   model.
2. **Run the task again — reads only.** A surface defect reproduces, because
   the misleading text is still there. A model error frequently does not.
   Disagreement between the two questions is itself worth recording: a task
   that fails sometimes usually means the surface is ambiguous rather than
   wrong, which is a weaker finding but still a finding.

   **Never replay a confirmed mutation to classify a transcript.** A repeated
   voucher batch mints a second set of guest credentials and a repeated power
   cycle is a second outage; even the writes that are idempotent cost a real
   write against a live network. Diagnosis is not worth that. For a mutating
   task, re-run the preview only, which is free, and otherwise classify on
   question 1 alone. A confirm step that can only be judged by doing it again
   is judged by reading instead.

Repair a surface defect by fixing the name, the description, or the parameter,
then re-run the task that caught it — under the same restriction: a mutating
task is re-verified from its preview, not by confirming a second time.
Changing the task to match the tools is the one repair that is never right. Record a model error and move on — it says
nothing about the surface, and treating it as a finding produces churn in the
tools to fix something the tools did not cause.

A task's **expected path** is a prediction, not part of the contract. If a run
shows the expected path was simply wrong about which tool should answer — the
route exists, just not the one written down — correct the expected path. That
is not the forbidden repair: the operator's question is what the task asserts,
and it stays exactly as it is.

## Safety

Some tasks mutate a live network. Three rules make that safe to run:

1. **Run the preview first and read it.** Every write here previews by default.
   The preview is part of the task: if it does not say what the change will do,
   that is a finding.
2. **Confirm only against a target the operator nominated for the exercise.**
   Do not block the first client the search returns, or reboot whatever access
   point looks slow. Pick a device that can be disrupted, and say which one
   before starting.
3. **Confirm each mutating task at most once per run.** Nothing about grading
   justifies a second confirm — not classifying an ambiguous transcript, not
   re-checking a task after the tools were fixed. The rule is blanket even
   though the tools are not all alike: the registry marks the client action,
   the device action, and the voucher mint as non-idempotent, and those are the
   ones a repeat genuinely doubles. The configuration writes do declare
   themselves idempotent, so a second confirm would leave the same state — but
   they still each cost a real write against a live network for no grading
   benefit. Everything after the first confirm is done by reading the preview
   and the result.

Tasks that mutate are marked. The rest are safe to run at any time.

## Reads and orientation

**"Is anything wrong with the network right now?"**
Expected: one overview call, and nothing else unless it reports something.
Watches for: an agent that fans out into per-device reads before it has a
reason to. The overview exists so the first question costs one call.

**"How many people are on the guest wifi?"**
Expected: a client search filtered by SSID, read from the result's total rather
than by counting rows.
Watches for: paging through every client to count them, which means the total
is not visible enough.

**"What's plugged into the switch in the office?"**
Expected: find the switch, inspect its port status and complete device record,
and read complete client records for controller-reported switch and port
references. `network.source.read` exposes original active-client fields;
`network.inventory.list/detail` exposes official client and device records.
Follow every page needed to establish the mapping.
Watches for: whether the agent distinguishes a reported attachment from a
guess based on port speed or client name. Missing attachment fields leave the
occupant unknown; they do not establish that the port is empty.

## Diagnosis

**"Why is the wifi bad in the back bedroom?"**
Expected: the diagnosis tool, then a targeted look at whatever it names.
Watches for: an agent that assembles a diagnosis by hand out of device and
client reads. If it does, the diagnosis tool is not discoverable, or does not
appear to answer the question actually asked.

**"Which client is using the most bandwidth?"**
Expected: a client search at full detail, ranked on the per-client byte
counters, **and said as what it is** — those counters have no verified common
start or reset interval, no rate, and no proven WAN-only scope. Uptime does not
establish a counter's start. Read `counterCoverage` and `counterSemantics`, and
never treat a missing counter as zero. So
they rank how much a client has moved, not how fast it is moving now. A laptop
connected all week can out-total the one saturating the link this minute. For
historical Internet volume, use `clientWanHistory` with fixed timestamps.
It ranks controller-attributed client usage and reports differences from site
WAN totals. This is useful attribution, but neither an instantaneous rate nor
proof of complete per-client collection. Its site graph timestamps do not
establish every client's observed interval.
Watches for: two ways to be confidently wrong. Whether the agent qualifies a
cumulative total as the volume it is instead of reporting it as current
bandwidth; and whether it notices that clients come back name-sorted and paged,
so a ranking means nothing until it holds the whole set. Answering from the
first page, or calling a week's accumulation "using the most bandwidth", both
look right. Reporting the volume ranking *and* naming the limit is the clean
outcome here — the surface cannot answer the question as literally asked, and
saying so is the correct answer, not a dead end.

**"What's using the most bandwidth on the network?"**
Expected: the top-applications report, read as the top-N contract it is.
Read `coverage` before interpreting the ranking: empty, unsupported, or
unrecognized DPI data must not be described as zero traffic or disabled DPI.
Read the source and `counterSemantics`: Activity attribution uses the requested
Internet-activity window but does not prove complete accounting. The legacy
DPI fallback has no verified common measurement window or WAN-only scope.
Watches for: whether the agent can tell a bounded top-N from a complete
census, and whether it carries that distinction into what it tells the
operator. The surface says which it returned; the transcript shows whether
that registered.

**"Did anything odd happen on the network last night?"**
Expected: an event search over a bounded window.
Watches for: whether the agent reports scan completeness and pages complete
source records when the compact search leaves the question unresolved.

## Audit

**"Is anything exposed to the internet that shouldn't be?"**
Expected: read the firewall and the port forwards, and reason about what is
open rather than reciting rows.
Watches for: whether the agent notices a truncated section and continues it.
A silently partial audit is the worst outcome this surface can produce, and
this task is the one that would catch it.

**"Are any of our wireless networks insecure?"**
Expected: read the networks, reason about the security modes.
Watches for: whether the agent reasons about the configured security mode
and uses passphrase values only as needed for the requested task.

**"We're on the zone-based firewall now — can you still see the old rules?"**
Expected: an answer that names the console's generation. What form that takes
comes from the capability probe and the original controller response. An
unsupported zone API must not be described as an empty rule list.
Watches for: this is the capability-detection boundary. If the agent comes away
believing the network has no firewall rules, the boundary has failed in the
exact way it exists to prevent. Grade the transcript on what the agent
concluded, not on which shape the tool used to tell it.

## Writes

Most of these are two tasks: the preview, then the confirm. Run the preview on
any target. Run the confirm only on a nominated one. One is marked preview
only, because the change the surface can actually make is broader than the
request — confirming it would be the failure the task exists to catch.

**"Turn off the guest network for tonight."** *(preview only — do not confirm)*
Expected: inspect the broadcast or WLAN configuration and its scheduling
fields, then preview a change matching the requested period. Official
broadcast blackout schedules and legacy WLAN schedules are exposed by their
configuration tools. Check the controller's schedule semantics and local time
before treating a recurring schedule as a single evening.
Watches for: whether the agent previews the requested duration and client
impact, or silently substitutes an indefinite disable or recurring outage.
If the controller cannot express the requested period, explain the observed
limit and leave that decision with the operator. Confirm this exercise only
if the operator nominates the target and accepts the preview.

**"Someone's kid is on the wifi past bedtime — cut them off."** *(mutates)*
Expected: find the client, preview the block, confirm.
Watches for: whether the agent can address a client after it is blocked. The
surface addresses clients by hardware address for exactly this reason, and this
task is where that choice pays off or does not.

**"Power-cycle whatever's on port 7 of the office switch."** *(mutates)*
Expected: identify the switch and port, inspect complete device and client
records for reported attachments, and preview the power cycle. State any
remaining uncertainty before confirming against the operator's nominated port.
Watches for: whether the agent infers an occupant from port speed or presents
incomplete client records as a complete attachment inventory. A controller
mapping is evidence; missing mapping fields leave the occupant unknown.

**"Make some guest passes for the weekend."** *(mutates — creates credentials)*
Expected: preview shows the batch — how many, how long, what limits — then a
confirmed call returns the codes and reports readback verification.
Watches for: whether the agent handles the codes as sensitive credentials and
uses `vouchers.status` or `vouchers.search` to inspect them later without
minting a second batch.

**"Turn that firewall policy back on."** *(mutates)*
Expected: preview says what the policy permits or blocks and that the whole
policy is resent, then confirm.
Watches for: whether the agent surfaces the overwrite window to the operator.
It is in the preview; the question is whether it survives into what the agent
says.

## Recording the results

Keep a transcript per task and a one-line verdict from the list above. The
useful output of a run is not a score — it is the list of names, descriptions,
and parameters that a real attempt tripped over.

Record what the run was against, once per run, or the verdicts do not compare:
the agent and model version, the deployed server revision, and the tool catalog
and schemas as the agent received them. The rubric leans on re-running a task
to separate a surface defect from a model error, and that inference is only
valid if both runs saw the same tools and the same model. Without these, a
result that changed because the surface improved is indistinguishable from one
that changed because the model did, and a run stops being comparable to the
one before it.

**Treat the transcripts themselves as sensitive, not just the voucher codes.**
The audit tasks call the firewall and network reads, whose results the registry
labels sensitive for good reason: they carry governed addresses, internal
destinations, subnets, SSIDs, and security modes. A kept run is therefore a
description of how the network is defended, in a file that outlives the calls
that produced it. Keep it where the console's own configuration would be kept
rather than in a scratch directory, do not paste it into an issue, a pull
request, or a chat log, and delete a run once its findings are recorded. The
findings are the durable artifact; the transcripts are working material.
