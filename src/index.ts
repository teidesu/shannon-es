/*
* Fold is how many register cycles need to be performed after combining the
* last byte of key and non-linear feedback, before every byte depends on every
* byte of the key. This depends on the feedback and nonlinear functions, and
* on where they are combined into the register. Making it same as the register
* length is a safe and conservative choice.
*/
const N = 16;
const FOLD = N; // How many iterations of folding to do.
const INITKONST = 0x6996c53a; // Value of konst to use during key loading.
const KEYP = 13; // Where to insert key/MAC/counter words.

const rotateLeft = function (i: number, distance: number) {
	return (i << distance) | (i >>> -distance);
}

/**
 * Nonlinear transform (sbox) of a word. There are two slightly different combinations.
 */
const sbox = function(i: number) {
	i ^= rotateLeft(i, 5) | rotateLeft(i, 7);
	i ^= rotateLeft(i, 19) | rotateLeft(i, 22);

	return i;
}

const sbox2 = function(i: number) {
	i ^= rotateLeft(i, 7) | rotateLeft(i, 22);
	i ^= rotateLeft(i, 5) | rotateLeft(i, 19);

	return i;
}

/**
 * Implementation of the Shannon stream-cipher.
 *
 * Based on original reference implementation in C.
 *
 * @author Felix Bruns <felixbruns@web.de>
 */
export class Shannon {
	constructor(key?: Uint8Array) {
		if (key) this.key(key)
	}

	R = new Int32Array(N); // Working storage for the shift register.
	CRC = new Int32Array(N); // Working storage for CRC accumulation.
	initR = new Int32Array(N); // Saved register contents.
	konst = 0; // Key dependant semi-constant.
	sbuf = 0;  // Encryption buffer.
	mbuf = 0;  // Partial word MAC buffer.
	nbuf = 0;  // Number of part-word stream bits buffered.

	/**
	 * Cycle the contents of the register and calculate output word in sbuf.
	 */
	private cycle() {
		// Temporary variable.
		let t = 0;

		// Nonlinear feedback function.
		t = this.R[12] ^ this.R[13] ^ this.konst;
		t = sbox(t) ^ rotateLeft(this.R[0], 1);

		// Shift register.
		for(let i = 1; i < N; i++) {
			this.R[i - 1] = this.R[i];
		}

		this.R[N - 1] = t;

		t = sbox2(this.R[2] ^ this.R[15]);
		this.R[0] ^= t;
		this.sbuf = t ^ this.R[8] ^ this.R[12];
	}

	/*
	 * The Shannon MAC function is modelled after the concepts of Phelix and SHA.
	 * Basically, words to be accumulated in the MAC are incorporated in two
	 * different ways:
	 * 1. They are incorporated into the stream cipher register at a place
	 *    where they will immediately have a nonlinear effect on the state.
	 * 2. They are incorporated into bit-parallel CRC-16 registers; the
	 *    contents of these registers will be used in MAC finalization.
	 */

	/**
	 * Accumulate a CRC of input words, later to be fed into MAC.
	 * This is actually 32 parallel CRC-16s, using the IBM CRC-16
	 * polynomian x^16 + x^15 + x^2 + 1
	 */
	private crcFunc(i: number) {
		// Temporary variable.
		let t = 0;

		// Accumulate CRC of input.
		t = this.CRC[0] ^ this.CRC[2] ^ this.CRC[15] ^ i;

		for(let j = 1; j < N; j++) {
			this.CRC[j - 1] = this.CRC[j];
		}

		this.CRC[N - 1] = t;
	}

	/**
	 * Normal MAC word processing: do both stream register and CRC.
	 */
	private macFunc(i: number) {
		this.crcFunc(i);

		this.R[KEYP] ^= i;
	}

	/**
	 * Initialize to known state.
	 */
	initState() {
		// Register initialized to Fibonacci numbers.
		this.R[0] = 1;
		this.R[1] = 1;

		for(let i = 2; i < N; i++) {
			this.R[i] = this.R[i - 1] + this.R[i - 2];
		}

		// Initialization constant.
		this.konst = INITKONST;
	}

	/**
	 * Save the current register state.
	 */
	saveState() {
		for(let i = 0; i < N; i++) {
			this.initR[i] = this.R[i];
		}
	}

	/**
	 * Inisialize to previously saved register state.
	 */
	reloadState() {
		for(let i = 0; i < N; i++) {
			this.R[i] = this.initR[i];
		}
	}

	/**
	 * Initialize 'konst'.
	 */
	genKonst() {
		this.konst = this.R[0];
	}

	/**
	 * Load key material into the register.
	 */
	addKey(k: number) {
		this.R[KEYP] ^= k;
	}

	/**
	 * Extra nonlinear diffusion of register for key and MAC.
	 */
	diffuse() {
		for(let i = 0; i < FOLD; i++) {
			this.cycle();
		}
	}

	/**
	 * Common actions for loading key material.
	 * Allow non-word-multiple key and nonce material.
	 * Note: Also initializes the CRC register as a side effect.
	 */
	loadKey(_key: Uint8Array) {
		let extra = new Uint8Array(4);
		let i = 0;
		let j = 0;
		let t = 0;

		// Start folding key.
		for(i = 0; i < (_key.length & ~0x03); i += 4) {
			// Shift 4 bytes into one word.
			t =	((_key[i + 3] & 0xFF) << 24) |
				((_key[i + 2] & 0xFF) << 16) |
				((_key[i + 1] & 0xFF) << 8) |
				((_key[i] & 0xFF));

			// Insert key word at index 13.
			this.addKey(t);

			// Cycle register.
			this.cycle();
		}

		// If there were any extra bytes, zero pad to a word.
		if(i < _key.length) {
			// i remains unchanged at start of loop.
			for(j = 0; i < _key.length; i++) {
				extra[j++] = _key[i];
			}

			// j remains unchanged at start of loop.
			for(; j < 4; j++) {
				extra[j] = 0;
			}

			// Shift 4 extra bytes into one word.
			t =	((extra[3] & 0xFF) << 24) |
				((extra[2] & 0xFF) << 16) |
				((extra[1] & 0xFF) << 8) |
				((extra[0] & 0xFF));

			// Insert key word at index 13.
			this.addKey(t);

			// Cycle register.
			this.cycle();
		}

		// Also fold in the length of the key.
		this.addKey(_key.length);

		// Cycle register.
		this.cycle();

		// Save a copy of the register.
		for(i = 0; i < N; i++) {
			this.CRC[i] = this.R[i];
		}

		// Now diffuse.
		this.diffuse();

		// Now XOR the copy back -- makes key loading irreversible.
		for(i = 0; i < N; i++) {
			this.R[i] ^= this.CRC[i];
		}
	}

	/**
	 * Set key
	 */
	key(_key: Uint8Array) {
		// Initializet known state.
		this.initState();

		// Load key material.
		this.loadKey(_key);

		// In case we proceed to stream generation.
		this.genKonst();

		// Save register state.
		this.saveState();

		// Set 'nbuf' value to zero.
		this.nbuf = 0;
	}

	/**
	 * Set IV
	 */
	nonce(_nonce: Uint8Array) {
		// Reload register state.
		this.reloadState();

		// Set initialization constant.
		this.konst = INITKONST;

		// Load "IV" material.
		this.loadKey(_nonce);

		// Set 'konst'.
		this.genKonst();

		// Set 'nbuf' value to zero.
		this.nbuf = 0;
	}

	nonce32(nonce: number) {
		let b = new Uint8Array(4);

		b[0] = (nonce >> 24) & 0xFF;
		b[1] = (nonce >> 16) & 0xFF;
		b[2] = (nonce >> 8) & 0xFF;
		b[3] = (nonce) & 0xFF;

		this.nonce(b);
	}

	/**
	 * XOR pseudo-random bytes into buffer.
	 * Note: doesn't play well with MAC functions.
	 */
	stream(buffer: Uint8Array, output = buffer) {
		let i = 0;
		let j = 0;
		let n = buffer.length;

		// Handle any previously buffered bytes.
		while(this.nbuf != 0 && n != 0) {
			output[i++] ^= this.sbuf & 0xFF;

			this.sbuf >>= 8;
			this.nbuf -= 8;

			n--;
		}

		// Handle whole words.
		j = n & ~0x03;

		while(i < j) {
			// Cycle register.
			this.cycle();

			// XOR word.
			output[i + 3] ^= (this.sbuf >> 24) & 0xFF;
			output[i + 2] ^= (this.sbuf >> 16) & 0xFF;
			output[i + 1] ^= (this.sbuf >>  8) & 0xFF;
			output[i] ^= (this.sbuf) & 0xFF;

			i += 4;
		}

		// Handle any trailing bytes.
		n &= 0x03;

		if(n != 0) {
			// Cycle register.
			this.cycle();

			this.nbuf = 32;

			while(this.nbuf != 0 && n != 0) {
				output[i++] ^= this.sbuf & 0xFF;

				this.sbuf >>= 8;
				this.nbuf -= 8;

				n--;
			}
		}

		return output;
	}

	/**
	 * Accumulate words into MAC without encryption.
	 * Note that plaintext is accumulated for MAC.
	 */
	macOnly(buffer: Uint8Array) {
		let i = 0;
		let j = 0;
		let n = buffer.length;
		let t = 0;

		// Handle any previously buffered bytes.
		if(this.nbuf != 0) {
			while(this.nbuf != 0 && n != 0) {
				this.mbuf ^= buffer[i++] << (32 - this.nbuf);
				this.nbuf -= 8;

				n--;
			}

			// Not a whole word yet.
			if(this.nbuf != 0) {
				return;
			}

			// LFSR already cycled.
			this.macFunc(this.mbuf);
		}

		// Handle whole words.
		j = n & ~0x03;

		while(i < j) {
			// Cycle register.
			this.cycle();

			// Shift 4 bytes into one word.
			t =	((buffer[i + 3] & 0xFF) << 24) |
				((buffer[i + 2] & 0xFF) << 16) |
				((buffer[i + 1] & 0xFF) << 8) |
				((buffer[i] & 0xFF));

			this.macFunc(t);

			i += 4;
		}

		// Handle any trailing bytes.
		n &= 0x03;

		if(n != 0) {
			// Cycle register.
			this.cycle();

			this.mbuf = 0;
			this.nbuf = 32;

			while(this.nbuf != 0 && n != 0) {
				this.mbuf ^= buffer[i++] << (32 - this.nbuf);
				this.nbuf -= 8;

				n--;
			}
		}

		return;
	}

	/**
	 * Combined MAC and encryption.
	 * Note that plaintext is accumulated for MAC.
	 */
	encrypt(buffer: Uint8Array, output = buffer) {
		let n = buffer.length;
		let i = 0;
		let j = 0;
		let t = 0;

		// Handle any previously buffered bytes.
		if(this.nbuf != 0) {
			while(this.nbuf != 0 && n != 0) {
				this.mbuf ^= (buffer[i] & 0xFF) << (32 - this.nbuf);
				output[i] ^= (this.sbuf >> (32 - this.nbuf)) & 0xFF;

				i++;

				this.nbuf -= 8;

				n--;
			}

			// Not a whole word yet.
			if(this.nbuf != 0) {
				return output;
			}

			// LFSR already cycled.
			this.macFunc(this.mbuf);
		}

		// Handle whole words.
		j = n & ~0x03;

		while(i < j) {
			// Cycle register.
			this.cycle();

			// Shift 4 bytes into one word.
			t =	((buffer[i + 3] & 0xFF) << 24) |
				((buffer[i + 2] & 0xFF) << 16) |
				((buffer[i + 1] & 0xFF) << 8) |
				((buffer[i] & 0xFF));

			this.macFunc(t);

			t ^= this.sbuf;

			// Put word into byte buffer.
			output[i + 3] = (t >> 24) & 0xFF;
			output[i + 2] = (t >> 16) & 0xFF;
			output[i + 1] = (t >>  8) & 0xFF;
			output[i] = (t) & 0xFF;

			i += 4;
		}

		// Handle any trailing bytes.
		n &= 0x03;

		if(n != 0) {
			// Cycle register.
			this.cycle();

			this.mbuf = 0;
			this.nbuf = 32;

			while(this.nbuf != 0 && n != 0) {
				this.mbuf ^= (buffer[i] & 0xFF) << (32 - this.nbuf);
				output[i] ^= (this.sbuf >> (32 - this.nbuf)) & 0xFF;

				i++;

				this.nbuf -= 8;

				n--;
			}
		}

		return output;
	}

	/**
	 * Combined MAC and decryption.
	 * Note that plaintext is accumulated for MAC.
	 */
	decrypt(buffer: Uint8Array, output = buffer) {
		let n = buffer.length;
		let i = 0;
		let j = 0;
		let t = 0;

		// Handle any previously buffered bytes.
		if(this.nbuf != 0) {
			while(this.nbuf != 0 && n != 0) {
				output[i] ^= (this.sbuf >> (32 - this.nbuf)) & 0xFF;
				this.mbuf ^= (buffer[i] & 0xFF) << (32 - this.nbuf);

				i++;

				this.nbuf -= 8;

				n--;
			}

			// Not a whole word yet.
			if(this.nbuf != 0) {
				return output;
			}

			// LFSR already cycled.
			this.macFunc(this.mbuf);
		}

		// Handle whole words.
		j = n & ~0x03;

		while(i < j) {
			// Cycle register.
			this.cycle();

			// Shift 4 bytes into one word.
			t =	((buffer[i + 3] & 0xFF) << 24) |
				((buffer[i + 2] & 0xFF) << 16) |
				((buffer[i + 1] & 0xFF) << 8) |
				((buffer[i] & 0xFF));

			t ^= this.sbuf;

			this.macFunc(t);

			// Put word into byte buffer.
			output[i + 3] = (t >> 24) & 0xFF;
			output[i + 2] = (t >> 16) & 0xFF;
			output[i + 1] = (t >>  8) & 0xFF;
			output[i] = (t) & 0xFF;

			i += 4;
		}

		// Handle any trailing bytes.
		n &= 0x03;

		if(n != 0) {
			// Cycle register.
			this.cycle();

			this.mbuf = 0;
			this.nbuf = 32;

			while(this.nbuf != 0 && n != 0) {
				buffer[i] ^= (this.sbuf >> (32 - this.nbuf)) & 0xFF;
				this.mbuf ^= (buffer[i] & 0xFF) << (32 - this.nbuf);

				i++;

				this.nbuf -= 8;

				n--;
			}
		}

		return output;
	}

	/**
	 * Having accumulated a MAC, finish processing and return it.
	 * Note that any unprocessed bytes are treated as if they were
	 * encrypted zero bytes, so plaintext (zero) is accumulated.
	 */
	finish(output: Uint8Array | number) {
		if (typeof output === 'number') output = new Uint8Array(output)
		let n = output.length
		let i = 0;
		let j = 0;

		// Handle any previously buffered bytes.
		if(this.nbuf != 0) {
			// LFSR already cycled.
			this.macFunc(this.mbuf);
		}

		/**
		 * Perturb the MAC to mark end of input.
		 * Note that only the stream register is updated, not the CRC.
		 * This is an action that can't be duplicated by passing in plaintext,
		 * hence defeating any kind of extension attack.
		 */
		this.cycle();
		this.addKey(INITKONST ^ (this.nbuf << 3));

		this.nbuf = 0;

		// Now add the CRC to the stream register and diffuse it.
		for(j = 0; j < N; j++) {
			this.R[j] ^= this.CRC[j];
		}

		this.diffuse();

		// Produce output from the stream buffer.
		while(n > 0) {
			this.cycle();

			if(n >= 4) {
				// Put word into byte buffer.
				output[i + 3] = (this.sbuf >> 24) & 0xFF;
				output[i + 2] = (this.sbuf >> 16) & 0xFF;
				output[i + 1] = (this.sbuf >>  8) & 0xFF;
				output[i] = (this.sbuf) & 0xFF;

				n -= 4;
				i += 4;
			} else {
				for(j = 0; j < n; j++) {
					output[i + j] = (this.sbuf >> (i * 8)) & 0xFF;
				}

				break;
			}
		}

		return output;
	}
}
