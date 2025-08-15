/**
 * SIWS Plugin Type Definitions
 */

export interface WalletAddress {
	id: string;
	userId: string;
	address: string;
	isPrimary: boolean;
	createdAt: Date;
}

export interface SIWSVerifyMessageArgs {
	message: string;
	signature: string;
	address: string;
}

export interface SNSLookupArgs {
	walletAddress: string;
}

export interface SNSLookupResult {
	name: string;
}
