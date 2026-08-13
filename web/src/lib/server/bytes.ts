// Byte conversions, in one place.
//
// Node's Buffer is typed as Uint8Array<ArrayBufferLike>, while Web Crypto requires
// Uint8Array<ArrayBuffer>: a Buffer may be backed by a SharedArrayBuffer, which
// the crypto API will not accept. Copying into a freshly allocated Uint8Array
// produces the narrower type, and does so by construction rather than by a cast
// that would silence the compiler without making the claim true.

export function fromBase64(value: string): Uint8Array<ArrayBuffer> {
	const buffer = Buffer.from(value, 'base64');
	// Reject anything that is not canonical base64. Buffer.from is famously lenient
	// and would silently accept a truncated key, producing a short one that "works"
	// until it has to decrypt something another replica wrote.
	if (buffer.toString('base64').replace(/=+$/, '') !== value.replace(/=+$/, '')) {
		throw new Error('not canonical base64');
	}
	return copy(buffer);
}

export function fromBase64Url(value: string): Uint8Array<ArrayBuffer> {
	return copy(Buffer.from(value, 'base64url'));
}

export function toBase64Url(bytes: Uint8Array): string {
	return Buffer.from(bytes).toString('base64url');
}

function copy(buffer: Buffer): Uint8Array<ArrayBuffer> {
	const out = new Uint8Array(buffer.byteLength);
	out.set(buffer);
	return out;
}
