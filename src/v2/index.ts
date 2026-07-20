import {
	createChallenge,
	solveChallenge,
	solveChallengeWorkers,
	verifySolution,
} from './pow.js';
import { verifyFieldsHash, verifyServerSignature } from './server-signature.js';
import { verifyServer } from './verify-server.js';
import { CappedMap } from './capped-map.js';
import { randomInt } from './helpers.js';
import { HmacAlgorithm } from './types.js';

export type * from './types.js';

export {
	CappedMap,
	HmacAlgorithm,
	createChallenge,
	randomInt,
	solveChallenge,
	solveChallengeWorkers,
	verifyFieldsHash,
	verifyServer,
	verifyServerSignature,
	verifySolution,
};

export default {
	CappedMap,
	HmacAlgorithm,
	createChallenge,
	randomInt,
	solveChallenge,
	solveChallengeWorkers,
	verifyFieldsHash,
	verifyServer,
	verifyServerSignature,
	verifySolution,
};
