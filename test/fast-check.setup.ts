import fc from "fast-check";

// Property tests are deterministic by default (see .kiro/steering/testing.md).
// fast-check prints the seed and the shrunk counterexample when a property fails.
// To explore more cases, or to replay a failure:
//   FC_SEED=123 FC_NUM_RUNS=10000 pnpm test
const seed = Number(process.env.FC_SEED ?? 20261204);
const numRuns = Number(process.env.FC_NUM_RUNS ?? 200);

fc.configureGlobal({ seed, numRuns });
