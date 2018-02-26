# Block-Chain-Code#ifndef AES_HELPER_H
#define AES_HELPER_H

/* $Id: aes_helper.c 220 2010-06-09 09:21:50Z tp $ */
/*
 * AES tables. This file is not meant to be compiled by itself; it
 * is included by some hash function implementations. It contains
 * the precomputed tables and helper macros for evaluating an AES
 * round, optionally with a final XOR with a subkey.
 *
 * By default, this file defines the tables and macros for little-endian
 * processing (i.e. it is assumed that the input bytes have been read
 * from memory and assembled with the little-endian convention). If
 * the 'AES_BIG_ENDIAN' macro is defined (to a non-zero integer value)
 * when this file is included, then the tables and macros for big-endian
 * processing are defined instead. The big-endian tables and macros have
 * names distinct from the little-endian tables and macros, hence it is
 * possible to have both simultaneously, by including this file twice
 * (with and without the AES_BIG_ENDIAN macro).
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * 
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * 
 */

#if AES_BIG_ENDIAN

#define AESx(x)   ( ((SPH_C32(x) >> 24) & SPH_C32(0x000000FF)) \
                  | ((SPH_C32(x) >>  8) & SPH_C32(0x0000FF00)) \
                  | ((SPH_C32(x) <<  8) & SPH_C32(0x00FF0000)) \
                  | ((SPH_C32(x) << 24) & SPH_C32(0xFF000000)))

#define AES0      AES0_BE
#define AES1      AES1_BE
#define AES2      AES2_BE
#define AES3      AES3_BE

#define AES_ROUND_BE(X0, X1, X2, X3, K0, K1, K2, K3, Y0, Y1, Y2, Y3)   do { \
		(Y0) = AES0[((X0) >> 24) & 0xFF] \
			^ AES1[((X1) >> 16) & 0xFF] \
			^ AES2[((X2) >> 8) & 0xFF] \
			^ AES3[(X3) & 0xFF] ^ (K0); \
		(Y1) = AES0[((X1) >> 24) & 0xFF] \
			^ AES1[((X2) >> 16) & 0xFF] \
			^ AES2[((X3) >> 8) & 0xFF] \
			^ AES3[(X0) & 0xFF] ^ (K1); \
		(Y2) = AES0[((X2) >> 24) & 0xFF] \
			^ AES1[((X3) >> 16) & 0xFF] \
			^ AES2[((X0) >> 8) & 0xFF] \
			^ AES3[(X1) & 0xFF] ^ (K2); \
		(Y3) = AES0[((X3) >> 24) & 0xFF] \
			^ AES1[((X0) >> 16) & 0xFF] \
			^ AES2[((X1) >> 8) & 0xFF] \
			^ AES3[(X2) & 0xFF] ^ (K3); \
	} while (0)

#define AES_ROUND_NOKEY_BE(X0, X1, X2, X3, Y0, Y1, Y2, Y3) \
	AES_ROUND_BE(X0, X1, X2, X3, 0, 0, 0, 0, Y0, Y1, Y2, Y3)

#else

#define AESx(x)   SPH_C32(x)
#define AES0      AES0_LE
#define AES1      AES1_LE
#define AES2      AES2_LE
#define AES3      AES3_LE

#define AES_ROUND_LE(X0, X1, X2, X3, K0, K1, K2, K3, Y0, Y1, Y2, Y3)   do { \
		(Y0) = AES0[(X0) & 0xFF] \
			^ AES1[((X1) >> 8) & 0xFF] \
			^ AES2[((X2) >> 16) & 0xFF] \
			^ AES3[((X3) >> 24) & 0xFF] ^ (K0); \
		(Y1) = AES0[(X1) & 0xFF] \
			^ AES1[((X2) >> 8) & 0xFF] \
			^ AES2[((X3) >> 16) & 0xFF] \
			^ AES3[((X0) >> 24) & 0xFF] ^ (K1); \
		(Y2) = AES0[(X2) & 0xFF] \
			^ AES1[((X3) >> 8) & 0xFF] \
			^ AES2[((X0) >> 16) & 0xFF] \
			^ AES3[((X1) >> 24) & 0xFF] ^ (K2); \
		(Y3) = AES0[(X3) & 0xFF] \
			^ AES1[((X0) >> 8) & 0xFF] \
			^ AES2[((X1) >> 16) & 0xFF] \
			^ AES3[((X2) >> 24) & 0xFF] ^ (K3); \
	} while (0)

#define AES_ROUND_NOKEY_LE(X0, X1, X2, X3, Y0, Y1, Y2, Y3) \
	AES_ROUND_LE(X0, X1, X2, X3, 0, 0, 0, 0, Y0, Y1, Y2, Y3)

#endif

/*
 * The AES*[] tables allow us to perform a fast evaluation of an AES
 * round; table AESi[] combines SubBytes for a byte at row i, and
 * MixColumns for the column where that byte goes after ShiftRows.
 */

__constant static const sph_u32 AES0_C[256] = {
	AESx(0xA56363C6), AESx(0x847C7CF8), AESx(0x997777EE), AESx(0x8D7B7BF6),
	AESx(0x0DF2F2FF), AESx(0xBD6B6BD6), AESx(0xB16F6FDE), AESx(0x54C5C591),
	AESx(0x50303060), AESx(0x03010102), AESx(0xA96767CE), AESx(0x7D2B2B56),
	AESx(0x19FEFEE7), AESx(0x62D7D7B5), AESx(0xE6ABAB4D), AESx(0x9A7676EC),
	AESx(0x45CACA8F), AESx(0x9D82821F), AESx(0x40C9C989), AESx(0x877D7DFA),
	AESx(0x15FAFAEF), AESx(0xEB5959B2), AESx(0xC947478E), AESx(0x0BF0F0FB),
	AESx(0xECADAD41), AESx(0x67D4D4B3), AESx(0xFDA2A25F), AESx(0xEAAFAF45),
	AESx(0xBF9C9C23), AESx(0xF7A4A453), AESx(0x967272E4), AESx(0x5BC0C09B),
	AESx(0xC2B7B775), AESx(0x1CFDFDE1), AESx(0xAE93933D), AESx(0x6A26264C),
	AESx(0x5A36366C), AESx(0x413F3F7E), AESx(0x02F7F7F5), AESx(0x4FCCCC83),
	AESx(0x5C343468), AESx(0xF4A5A551), AESx(0x34E5E5D1), AESx(0x08F1F1F9),
	AESx(0x937171E2), AESx(0x73D8D8AB), AESx(0x53313162), AESx(0x3F15152A),
	AESx(0x0C040408), AESx(0x52C7C795), AESx(0x65232346), AESx(0x5EC3C39D),
	AESx(0x28181830), AESx(0xA1969637), AESx(0x0F05050A), AESx(0xB59A9A2F),
	AESx(0x0907070E), AESx(0x36121224), AESx(0x9B80801B), AESx(0x3DE2E2DF),
	AESx(0x26EBEBCD), AESx(0x6927274E), AESx(0xCDB2B27F), AESx(0x9F7575EA),
	AESx(0x1B090912), AESx(0x9E83831D), AESx(0x742C2C58), AESx(0x2E1A1A34),
	AESx(0x2D1B1B36), AESx(0xB26E6EDC), AESx(0xEE5A5AB4), AESx(0xFBA0A05B),
	AESx(0xF65252A4), AESx(0x4D3B3B76), AESx(0x61D6D6B7), AESx(0xCEB3B37D),
	AESx(0x7B292952), AESx(0x3EE3E3DD), AESx(0x712F2F5E), AESx(0x97848413),
	AESx(0xF55353A6), AESx(0x68D1D1B9), AESx(0x00000000), AESx(0x2CEDEDC1),
	AESx(0x60202040), AESx(0x1FFCFCE3), AESx(0xC8B1B179), AESx(0xED5B5BB6),
	AESx(0xBE6A6AD4), AESx(0x46CBCB8D), AESx(0xD9BEBE67), AESx(0x4B393972),
	AESx(0xDE4A4A94), AESx(0xD44C4C98), AESx(0xE85858B0), AESx(0x4ACFCF85),
	AESx(0x6BD0D0BB), AESx(0x2AEFEFC5), AESx(0xE5AAAA4F), AESx(0x16FBFBED),
	AESx(0xC5434386), AESx(0xD74D4D9A), AESx(0x55333366), AESx(0x94858511),
	AESx(0xCF45458A), AESx(0x10F9F9E9), AESx(0x06020204), AESx(0x817F7FFE),
	AESx(0xF05050A0), AESx(0x443C3C78), AESx(0xBA9F9F25), AESx(0xE3A8A84B),
	AESx(0xF35151A2), AESx(0xFEA3A35D), AESx(0xC0404080), AESx(0x8A8F8F05),
	AESx(0xAD92923F), AESx(0xBC9D9D21), AESx(0x48383870), AESx(0x04F5F5F1),
	AESx(0xDFBCBC63), AESx(0xC1B6B677), AESx(0x75DADAAF), AESx(0x63212142),
	AESx(0x30101020), AESx(0x1AFFFFE5), AESx(0x0EF3F3FD), AESx(0x6DD2D2BF),
	AESx(0x4CCDCD81), AESx(0x140C0C18), AESx(0x35131326), AESx(0x2FECECC3),
	AESx(0xE15F5FBE), AESx(0xA2979735), AESx(0xCC444488), AESx(0x3917172E),
	AESx(0x57C4C493), AESx(0xF2A7A755), AESx(0x827E7EFC), AESx(0x473D3D7A),
	AESx(0xAC6464C8), AESx(0xE75D5DBA), AESx(0x2B191932), AESx(0x957373E6),
	AESx(0xA06060C0), AESx(0x98818119), AESx(0xD14F4F9E), AESx(0x7FDCDCA3),
	AESx(0x66222244), AESx(0x7E2A2A54), AESx(0xAB90903B), AESx(0x8388880B),
	AESx(0xCA46468C), AESx(0x29EEEEC7), AESx(0xD3B8B86B), AESx(0x3C141428),
	AESx(0x79DEDEA7), AESx(0xE25E5EBC), AESx(0x1D0B0B16), AESx(0x76DBDBAD),
	AESx(0x3BE0E0DB), AESx(0x56323264), AESx(0x4E3A3A74), AESx(0x1E0A0A14),
	AESx(0xDB494992), AESx(0x0A06060C), AESx(0x6C242448), AESx(0xE45C5CB8),
	AESx(0x5DC2C29F), AESx(0x6ED3D3BD), AESx(0xEFACAC43), AESx(0xA66262C4),
	AESx(0xA8919139), AESx(0xA4959531), AESx(0x37E4E4D3), AESx(0x8B7979F2),
	AESx(0x32E7E7D5), AESx(0x43C8C88B), AESx(0x5937376E), AESx(0xB76D6DDA),
	AESx(0x8C8D8D01), AESx(0x64D5D5B1), AESx(0xD24E4E9C), AESx(0xE0A9A949),
	AESx(0xB46C6CD8), AESx(0xFA5656AC), AESx(0x07F4F4F3), AESx(0x25EAEACF),
	AESx(0xAF6565CA), AESx(0x8E7A7AF4), AESx(0xE9AEAE47), AESx(0x18080810),
	AESx(0xD5BABA6F), AESx(0x887878F0), AESx(0x6F25254A), AESx(0x722E2E5C),
	AESx(0x241C1C38), AESx(0xF1A6A657), AESx(0xC7B4B473), AESx(0x51C6C697),
	AESx(0x23E8E8CB), AESx(0x7CDDDDA1), AESx(0x9C7474E8), AESx(0x211F1F3E),
	AESx(0xDD4B4B96), AESx(0xDCBDBD61), AESx(0x868B8B0D), AESx(0x858A8A0F),
	AESx(0x907070E0), AESx(0x423E3E7C), AESx(0xC4B5B571), AESx(0xAA6666CC),
	AESx(0xD8484890), AESx(0x05030306), AESx(0x01F6F6F7), AESx(0x120E0E1C),
	AESx(0xA36161C2), AESx(0x5F35356A), AESx(0xF95757AE), AESx(0xD0B9B969),
	AESx(0x91868617), AESx(0x58C1C199), AESx(0x271D1D3A), AESx(0xB99E9E27),
	AESx(0x38E1E1D9), AESx(0x13F8F8EB), AESx(0xB398982B), AESx(0x33111122),
	AESx(0xBB6969D2), AESx(0x70D9D9A9), AESx(0x898E8E07), AESx(0xA7949433),
	AESx(0xB69B9B2D), AESx(0x221E1E3C), AESx(0x92878715), AESx(0x20E9E9C9),
	AESx(0x49CECE87), AESx(0xFF5555AA), AESx(0x78282850), AESx(0x7ADFDFA5),
	AESx(0x8F8C8C03), AESx(0xF8A1A159), AESx(0x80898909), AESx(0x170D0D1A),
	AESx(0xDABFBF65), AESx(0x31E6E6D7), AESx(0xC6424284), AESx(0xB86868D0),
	AESx(0xC3414182), AESx(0xB0999929), AESx(0x772D2D5A), AESx(0x110F0F1E),
	AESx(0xCBB0B07B), AESx(0xFC5454A8), AESx(0xD6BBBB6D), AESx(0x3A16162C)
};

__constant static const sph_u32 AES1_C[256] = {
	AESx(0x6363C6A5), AESx(0x7C7CF884), AESx(0x7777EE99), AESx(0x7B7BF68D),
	AESx(0xF2F2FF0D), AESx(0x6B6BD6BD), AESx(0x6F6FDEB1), AESx(0xC5C59154),
	AESx(0x30306050), AESx(0x01010203), AESx(0x6767CEA9), AESx(0x2B2B567D),
	AESx(0xFEFEE719), AESx(0xD7D7B562), AESx(0xABAB4DE6), AESx(0x7676EC9A),
	AESx(0xCACA8F45), AESx(0x82821F9D), AESx(0xC9C98940), AESx(0x7D7DFA87),
	AESx(0xFAFAEF15), AESx(0x5959B2EB), AESx(0x47478EC9), AESx(0xF0F0FB0B),
	AESx(0xADAD41EC), AESx(0xD4D4B367), AESx(0xA2A25FFD), AESx(0xAFAF45EA),
	AESx(0x9C9C23BF), AESx(0xA4A453F7), AESx(0x7272E496), AESx(0xC0C09B5B),
	AESx(0xB7B775C2), AESx(0xFDFDE11C), AESx(0x93933DAE), AESx(0x26264C6A),
	AESx(0x36366C5A), AESx(0x3F3F7E41), AESx(0xF7F7F502), AESx(0xCCCC834F),
	AESx(0x3434685C), AESx(0xA5A551F4), AESx(0xE5E5D134), AESx(0xF1F1F908),
	AESx(0x7171E293), AESx(0xD8D8AB73), AESx(0x31316253), AESx(0x15152A3F),
	AESx(0x0404080C), AESx(0xC7C79552), AESx(0x23234665), AESx(0xC3C39D5E),
	AESx(0x18183028), AESx(0x969637A1), AESx(0x05050A0F), AESx(0x9A9A2FB5),
	AESx(0x07070E09), AESx(0x12122436), AESx(0x80801B9B), AESx(0xE2E2DF3D),
	AESx(0xEBEBCD26), AESx(0x27274E69), AESx(0xB2B27FCD), AESx(0x7575EA9F),
	AESx(0x0909121B), AESx(0x83831D9E), AESx(0x2C2C5874), AESx(0x1A1A342E),
	AESx(0x1B1B362D), AESx(0x6E6EDCB2), AESx(0x5A5AB4EE), AESx(0xA0A05BFB),
	AESx(0x5252A4F6), AESx(0x3B3B764D), AESx(0xD6D6B761), AESx(0xB3B37DCE),
	AESx(0x2929527B), AESx(0xE3E3DD3E), AESx(0x2F2F5E71), AESx(0x84841397),
	AESx(0x5353A6F5), AESx(0xD1D1B968), AESx(0x00000000), AESx(0xEDEDC12C),
	AESx(0x20204060), AESx(0xFCFCE31F), AESx(0xB1B179C8), AESx(0x5B5BB6ED),
	AESx(0x6A6AD4BE), AESx(0xCBCB8D46), AESx(0xBEBE67D9), AESx(0x3939724B),
	AESx(0x4A4A94DE), AESx(0x4C4C98D4), AESx(0x5858B0E8), AESx(0xCFCF854A),
	AESx(0xD0D0BB6B), AESx(0xEFEFC52A), AESx(0xAAAA4FE5), AESx(0xFBFBED16),
	AESx(0x434386C5), AESx(0x4D4D9AD7), AESx(0x33336655), AESx(0x85851194),
	AESx(0x45458ACF), AESx(0xF9F9E910), AESx(0x02020406), AESx(0x7F7FFE81),
	AESx(0x5050A0F0), AESx(0x3C3C7844), AESx(0x9F9F25BA), AESx(0xA8A84BE3),
	AESx(0x5151A2F3), AESx(0xA3A35DFE), AESx(0x404080C0), AESx(0x8F8F058A),
	AESx(0x92923FAD), AESx(0x9D9D21BC), AESx(0x38387048), AESx(0xF5F5F104),
	AESx(0xBCBC63DF), AESx(0xB6B677C1), AESx(0xDADAAF75), AESx(0x21214263),
	AESx(0x10102030), AESx(0xFFFFE51A), AESx(0xF3F3FD0E), AESx(0xD2D2BF6D),
	AESx(0xCDCD814C), AESx(0x0C0C1814), AESx(0x13132635), AESx(0xECECC32F),
	AESx(0x5F5FBEE1), AESx(0x979735A2), AESx(0x444488CC), AESx(0x17172E39),
	AESx(0xC4C49357), AESx(0xA7A755F2), AESx(0x7E7EFC82), AESx(0x3D3D7A47),
	AESx(0x6464C8AC), AESx(0x5D5DBAE7), AESx(0x1919322B), AESx(0x7373E695),
	AESx(0x6060C0A0), AESx(0x81811998), AESx(0x4F4F9ED1), AESx(0xDCDCA37F),
	AESx(0x22224466), AESx(0x2A2A547E), AESx(0x90903BAB), AESx(0x88880B83),
	AESx(0x46468CCA), AESx(0xEEEEC729), AESx(0xB8B86BD3), AESx(0x1414283C),
	AESx(0xDEDEA779), AESx(0x5E5EBCE2), AESx(0x0B0B161D), AESx(0xDBDBAD76),
	AESx(0xE0E0DB3B), AESx(0x32326456), AESx(0x3A3A744E), AESx(0x0A0A141E),
	AESx(0x494992DB), AESx(0x06060C0A), AESx(0x2424486C), AESx(0x5C5CB8E4),
	AESx(0xC2C29F5D), AESx(0xD3D3BD6E), AESx(0xACAC43EF), AESx(0x6262C4A6),
	AESx(0x919139A8), AESx(0x959531A4), AESx(0xE4E4D337), AESx(0x7979F28B),
	AESx(0xE7E7D532), AESx(0xC8C88B43), AESx(0x37376E59), AESx(0x6D6DDAB7),
	AESx(0x8D8D018C), AESx(0xD5D5B164), AESx(0x4E4E9CD2), AESx(0xA9A949E0),
	AESx(0x6C6CD8B4), AESx(0x5656ACFA), AESx(0xF4F4F307), AESx(0xEAEACF25),
	AESx(0x6565CAAF), AESx(0x7A7AF48E), AESx(0xAEAE47E9), AESx(0x08081018),
	AESx(0xBABA6FD5), AESx(0x7878F088), AESx(0x25254A6F), AESx(0x2E2E5C72),
	AESx(0x1C1C3824), AESx(0xA6A657F1), AESx(0xB4B473C7), AESx(0xC6C69751),
	AESx(0xE8E8CB23), AESx(0xDDDDA17C), AESx(0x7474E89C), AESx(0x1F1F3E21),
	AESx(0x4B4B96DD), AESx(0xBDBD61DC), AESx(0x8B8B0D86), AESx(0x8A8A0F85),
	AESx(0x7070E090), AESx(0x3E3E7C42), AESx(0xB5B571C4), AESx(0x6666CCAA),
	AESx(0x484890D8), AESx(0x03030605), AESx(0xF6F6F701), AESx(0x0E0E1C12),
	AESx(0x6161C2A3), AESx(0x35356A5F), AESx(0x5757AEF9), AESx(0xB9B969D0),
	AESx(0x86861791), AESx(0xC1C19958), AESx(0x1D1D3A27), AESx(0x9E9E27B9),
	AESx(0xE1E1D938), AESx(0xF8F8EB13), AESx(0x98982BB3), AESx(0x11112233),
	AESx(0x6969D2BB), AESx(0xD9D9A970), AESx(0x8E8E0789), AESx(0x949433A7),
	AESx(0x9B9B2DB6), AESx(0x1E1E3C22), AESx(0x87871592), AESx(0xE9E9C920),
	AESx(0xCECE8749), AESx(0x5555AAFF), AESx(0x28285078), AESx(0xDFDFA57A),
	AESx(0x8C8C038F), AESx(0xA1A159F8), AESx(0x89890980), AESx(0x0D0D1A17),
	AESx(0xBFBF65DA), AESx(0xE6E6D731), AESx(0x424284C6), AESx(0x6868D0B8),
	AESx(0x414182C3), AESx(0x999929B0), AESx(0x2D2D5A77), AESx(0x0F0F1E11),
	AESx(0xB0B07BCB), AESx(0x5454A8FC), AESx(0xBBBB6DD6), AESx(0x16162C3A)
};

__constant static const sph_u32 AES2_C[256] = {
	AESx(0x63C6A563), AESx(0x7CF8847C), AESx(0x77EE9977), AESx(0x7BF68D7B),
	AESx(0xF2FF0DF2), AESx(0x6BD6BD6B), AESx(0x6FDEB16F), AESx(0xC59154C5),
	AESx(0x30605030), AESx(0x01020301), AESx(0x67CEA967), AESx(0x2B567D2B),
	AESx(0xFEE719FE), AESx(0xD7B562D7), AESx(0xAB4DE6AB), AESx(0x76EC9A76),
	AESx(0xCA8F45CA), AESx(0x821F9D82), AESx(0xC98940C9), AESx(0x7DFA877D),
	AESx(0xFAEF15FA), AESx(0x59B2EB59), AESx(0x478EC947), AESx(0xF0FB0BF0),
	AESx(0xAD41ECAD), AESx(0xD4B367D4), AESx(0xA25FFDA2), AESx(0xAF45EAAF),
	AESx(0x9C23BF9C), AESx(0xA453F7A4), AESx(0x72E49672), AESx(0xC09B5BC0),
	AESx(0xB775C2B7), AESx(0xFDE11CFD), AESx(0x933DAE93), AESx(0x264C6A26),
	AESx(0x366C5A36), AESx(0x3F7E413F), AESx(0xF7F502F7), AESx(0xCC834FCC),
	AESx(0x34685C34), AESx(0xA551F4A5), AESx(0xE5D134E5), AESx(0xF1F908F1),
	AESx(0x71E29371), AESx(0xD8AB73D8), AESx(0x31625331), AESx(0x152A3F15),
	AESx(0x04080C04), AESx(0xC79552C7), AESx(0x23466523), AESx(0xC39D5EC3),
	AESx(0x18302818), AESx(0x9637A196), AESx(0x050A0F05), AESx(0x9A2FB59A),
	AESx(0x070E0907), AESx(0x12243612), AESx(0x801B9B80), AESx(0xE2DF3DE2),
	AESx(0xEBCD26EB), AESx(0x274E6927), AESx(0xB27FCDB2), AESx(0x75EA9F75),
	AESx(0x09121B09), AESx(0x831D9E83), AESx(0x2C58742C), AESx(0x1A342E1A),
	AESx(0x1B362D1B), AESx(0x6EDCB26E), AESx(0x5AB4EE5A), AESx(0xA05BFBA0),
	AESx(0x52A4F652), AESx(0x3B764D3B), AESx(0xD6B761D6), AESx(0xB37DCEB3),
	AESx(0x29527B29), AESx(0xE3DD3EE3), AESx(0x2F5E712F), AESx(0x84139784),
	AESx(0x53A6F553), AESx(0xD1B968D1), AESx(0x00000000), AESx(0xEDC12CED),
	AESx(0x20406020), AESx(0xFCE31FFC), AESx(0xB179C8B1), AESx(0x5BB6ED5B),
	AESx(0x6AD4BE6A), AESx(0xCB8D46CB), AESx(0xBE67D9BE), AESx(0x39724B39),
	AESx(0x4A94DE4A), AESx(0x4C98D44C), AESx(0x58B0E858), AESx(0xCF854ACF),
	AESx(0xD0BB6BD0), AESx(0xEFC52AEF), AESx(0xAA4FE5AA), AESx(0xFBED16FB),
	AESx(0x4386C543), AESx(0x4D9AD74D), AESx(0x33665533), AESx(0x85119485),
	AESx(0x458ACF45), AESx(0xF9E910F9), AESx(0x02040602), AESx(0x7FFE817F),
	AESx(0x50A0F050), AESx(0x3C78443C), AESx(0x9F25BA9F), AESx(0xA84BE3A8),
	AESx(0x51A2F351), AESx(0xA35DFEA3), AESx(0x4080C040), AESx(0x8F058A8F),
	AESx(0x923FAD92), AESx(0x9D21BC9D), AESx(0x38704838), AESx(0xF5F104F5),
	AESx(0xBC63DFBC), AESx(0xB677C1B6), AESx(0xDAAF75DA), AESx(0x21426321),
	AESx(0x10203010), AESx(0xFFE51AFF), AESx(0xF3FD0EF3), AESx(0xD2BF6DD2),
	AESx(0xCD814CCD), AESx(0x0C18140C), AESx(0x13263513), AESx(0xECC32FEC),
	AESx(0x5FBEE15F), AESx(0x9735A297), AESx(0x4488CC44), AESx(0x172E3917),
	AESx(0xC49357C4), AESx(0xA755F2A7), AESx(0x7EFC827E), AESx(0x3D7A473D),
	AESx(0x64C8AC64), AESx(0x5DBAE75D), AESx(0x19322B19), AESx(0x73E69573),
	AESx(0x60C0A060), AESx(0x81199881), AESx(0x4F9ED14F), AESx(0xDCA37FDC),
	AESx(0x22446622), AESx(0x2A547E2A), AESx(0x903BAB90), AESx(0x880B8388),
	AESx(0x468CCA46), AESx(0xEEC729EE), AESx(0xB86BD3B8), AESx(0x14283C14),
	AESx(0xDEA779DE), AESx(0x5EBCE25E), AESx(0x0B161D0B), AESx(0xDBAD76DB),
	AESx(0xE0DB3BE0), AESx(0x32645632), AESx(0x3A744E3A), AESx(0x0A141E0A),
	AESx(0x4992DB49), AESx(0x060C0A06), AESx(0x24486C24), AESx(0x5CB8E45C),
	AESx(0xC29F5DC2), AESx(0xD3BD6ED3), AESx(0xAC43EFAC), AESx(0x62C4A662),
	AESx(0x9139A891), AESx(0x9531A495), AESx(0xE4D337E4), AESx(0x79F28B79),
	AESx(0xE7D532E7), AESx(0xC88B43C8), AESx(0x376E5937), AESx(0x6DDAB76D),
	AESx(0x8D018C8D), AESx(0xD5B164D5), AESx(0x4E9CD24E), AESx(0xA949E0A9),
	AESx(0x6CD8B46C), AESx(0x56ACFA56), AESx(0xF4F307F4), AESx(0xEACF25EA),
	AESx(0x65CAAF65), AESx(0x7AF48E7A), AESx(0xAE47E9AE), AESx(0x08101808),
	AESx(0xBA6FD5BA), AESx(0x78F08878), AESx(0x254A6F25), AESx(0x2E5C722E),
	AESx(0x1C38241C), AESx(0xA657F1A6), AESx(0xB473C7B4), AESx(0xC69751C6),
	AESx(0xE8CB23E8), AESx(0xDDA17CDD), AESx(0x74E89C74), AESx(0x1F3E211F),
	AESx(0x4B96DD4B), AESx(0xBD61DCBD), AESx(0x8B0D868B), AESx(0x8A0F858A),
	AESx(0x70E09070), AESx(0x3E7C423E), AESx(0xB571C4B5), AESx(0x66CCAA66),
	AESx(0x4890D848), AESx(0x03060503), AESx(0xF6F701F6), AESx(0x0E1C120E),
	AESx(0x61C2A361), AESx(0x356A5F35), AESx(0x57AEF957), AESx(0xB969D0B9),
	AESx(0x86179186), AESx(0xC19958C1), AESx(0x1D3A271D), AESx(0x9E27B99E),
	AESx(0xE1D938E1), AESx(0xF8EB13F8), AESx(0x982BB398), AESx(0x11223311),
	AESx(0x69D2BB69), AESx(0xD9A970D9), AESx(0x8E07898E), AESx(0x9433A794),
	AESx(0x9B2DB69B), AESx(0x1E3C221E), AESx(0x87159287), AESx(0xE9C920E9),
	AESx(0xCE8749CE), AESx(0x55AAFF55), AESx(0x28507828), AESx(0xDFA57ADF),
	AESx(0x8C038F8C), AESx(0xA159F8A1), AESx(0x89098089), AESx(0x0D1A170D),
	AESx(0xBF65DABF), AESx(0xE6D731E6), AESx(0x4284C642), AESx(0x68D0B868),
	AESx(0x4182C341), AESx(0x9929B099), AESx(0x2D5A772D), AESx(0x0F1E110F),
	AESx(0xB07BCBB0), AESx(0x54A8FC54), AESx(0xBB6DD6BB), AESx(0x162C3A16)
};

__constant static const sph_u32 AES3_C[256] = {
	AESx(0xC6A56363), AESx(0xF8847C7C), AESx(0xEE997777), AESx(0xF68D7B7B),
	AESx(0xFF0DF2F2), AESx(0xD6BD6B6B), AESx(0xDEB16F6F), AESx(0x9154C5C5),
	AESx(0x60503030), AESx(0x02030101), AESx(0xCEA96767), AESx(0x567D2B2B),
	AESx(0xE719FEFE), AESx(0xB562D7D7), AESx(0x4DE6ABAB), AESx(0xEC9A7676),
	AESx(0x8F45CACA), AESx(0x1F9D8282), AESx(0x8940C9C9), AESx(0xFA877D7D),
	AESx(0xEF15FAFA), AESx(0xB2EB5959), AESx(0x8EC94747), AESx(0xFB0BF0F0),
	AESx(0x41ECADAD), AESx(0xB367D4D4), AESx(0x5FFDA2A2), AESx(0x45EAAFAF),
	AESx(0x23BF9C9C), AESx(0x53F7A4A4), AESx(0xE4967272), AESx(0x9B5BC0C0),
	AESx(0x75C2B7B7), AESx(0xE11CFDFD), AESx(0x3DAE9393), AESx(0x4C6A2626),
	AESx(0x6C5A3636), AESx(0x7E413F3F), AESx(0xF502F7F7), AESx(0x834FCCCC),
	AESx(0x685C3434), AESx(0x51F4A5A5), AESx(0xD134E5E5), AESx(0xF908F1F1),
	AESx(0xE2937171), AESx(0xAB73D8D8), AESx(0x62533131), AESx(0x2A3F1515),
	AESx(0x080C0404), AESx(0x9552C7C7), AESx(0x46652323), AESx(0x9D5EC3C3),
	AESx(0x30281818), AESx(0x37A19696), AESx(0x0A0F0505), AESx(0x2FB59A9A),
	AESx(0x0E090707), AESx(0x24361212), AESx(0x1B9B8080), AESx(0xDF3DE2E2),
	AESx(0xCD26EBEB), AESx(0x4E692727), AESx(0x7FCDB2B2), AESx(0xEA9F7575),
	AESx(0x121B0909), AESx(0x1D9E8383), AESx(0x58742C2C), AESx(0x342E1A1A),
	AESx(0x362D1B1B), AESx(0xDCB26E6E), AESx(0xB4EE5A5A), AESx(0x5BFBA0A0),
	AESx(0xA4F65252), AESx(0x764D3B3B), AESx(0xB761D6D6), AESx(0x7DCEB3B3),
	AESx(0x527B2929), AESx(0xDD3EE3E3), AESx(0x5E712F2F), AESx(0x13978484),
	AESx(0xA6F55353), AESx(0xB968D1D1), AESx(0x00000000), AESx(0xC12CEDED),
	AESx(0x40602020), AESx(0xE31FFCFC), AESx(0x79C8B1B1), AESx(0xB6ED5B5B),
	AESx(0xD4BE6A6A), AESx(0x8D46CBCB), AESx(0x67D9BEBE), AESx(0x724B3939),
	AESx(0x94DE4A4A), AESx(0x98D44C4C), AESx(0xB0E85858), AESx(0x854ACFCF),
	AESx(0xBB6BD0D0), AESx(0xC52AEFEF), AESx(0x4FE5AAAA), AESx(0xED16FBFB),
	AESx(0x86C54343), AESx(0x9AD74D4D), AESx(0x66553333), AESx(0x11948585),
	AESx(0x8ACF4545), AESx(0xE910F9F9), AESx(0x04060202), AESx(0xFE817F7F),
	AESx(0xA0F05050), AESx(0x78443C3C), AESx(0x25BA9F9F), AESx(0x4BE3A8A8),
	AESx(0xA2F35151), AESx(0x5DFEA3A3), AESx(0x80C04040), AESx(0x058A8F8F),
	AESx(0x3FAD9292), AESx(0x21BC9D9D), AESx(0x70483838), AESx(0xF104F5F5),
	AESx(0x63DFBCBC), AESx(0x77C1B6B6), AESx(0xAF75DADA), AESx(0x42632121),
	AESx(0x20301010), AESx(0xE51AFFFF), AESx(0xFD0EF3F3), AESx(0xBF6DD2D2),
	AESx(0x814CCDCD), AESx(0x18140C0C), AESx(0x26351313), AESx(0xC32FECEC),
	AESx(0xBEE15F5F), AESx(0x35A29797), AESx(0x88CC4444), AESx(0x2E391717),
	AESx(0x9357C4C4), AESx(0x55F2A7A7), AESx(0xFC827E7E), AESx(0x7A473D3D),
	AESx(0xC8AC6464), AESx(0xBAE75D5D), AESx(0x322B1919), AESx(0xE6957373),
	AESx(0xC0A06060), AESx(0x19988181), AESx(0x9ED14F4F), AESx(0xA37FDCDC),
	AESx(0x44662222), AESx(0x547E2A2A), AESx(0x3BAB9090), AESx(0x0B838888),
	AESx(0x8CCA4646), AESx(0xC729EEEE), AESx(0x6BD3B8B8), AESx(0x283C1414),
	AESx(0xA779DEDE), AESx(0xBCE25E5E), AESx(0x161D0B0B), AESx(0xAD76DBDB),
	AESx(0xDB3BE0E0), AESx(0x64563232), AESx(0x744E3A3A), AESx(0x141E0A0A),
	AESx(0x92DB4949), AESx(0x0C0A0606), AESx(0x486C2424), AESx(0xB8E45C5C),
	AESx(0x9F5DC2C2), AESx(0xBD6ED3D3), AESx(0x43EFACAC), AESx(0xC4A66262),
	AESx(0x39A89191), AESx(0x31A49595), AESx(0xD337E4E4), AESx(0xF28B7979),
	AESx(0xD532E7E7), AESx(0x8B43C8C8), AESx(0x6E593737), AESx(0xDAB76D6D),
	AESx(0x018C8D8D), AESx(0xB164D5D5), AESx(0x9CD24E4E), AESx(0x49E0A9A9),
	AESx(0xD8B46C6C), AESx(0xACFA5656), AESx(0xF307F4F4), AESx(0xCF25EAEA),
	AESx(0xCAAF6565), AESx(0xF48E7A7A), AESx(0x47E9AEAE), AESx(0x10180808),
	AESx(0x6FD5BABA), AESx(0xF0887878), AESx(0x4A6F2525), AESx(0x5C722E2E),
	AESx(0x38241C1C), AESx(0x57F1A6A6), AESx(0x73C7B4B4), AESx(0x9751C6C6),
	AESx(0xCB23E8E8), AESx(0xA17CDDDD), AESx(0xE89C7474), AESx(0x3E211F1F),
	AESx(0x96DD4B4B), AESx(0x61DCBDBD), AESx(0x0D868B8B), AESx(0x0F858A8A),
	AESx(0xE0907070), AESx(0x7C423E3E), AESx(0x71C4B5B5), AESx(0xCCAA6666),
	AESx(0x90D84848), AESx(0x06050303), AESx(0xF701F6F6), AESx(0x1C120E0E),
	AESx(0xC2A36161), AESx(0x6A5F3535), AESx(0xAEF95757), AESx(0x69D0B9B9),
	AESx(0x17918686), AESx(0x9958C1C1), AESx(0x3A271D1D), AESx(0x27B99E9E),
	AESx(0xD938E1E1), AESx(0xEB13F8F8), AESx(0x2BB39898), AESx(0x22331111),
	AESx(0xD2BB6969), AESx(0xA970D9D9), AESx(0x07898E8E), AESx(0x33A79494),
	AESx(0x2DB69B9B), AESx(0x3C221E1E), AESx(0x15928787), AESx(0xC920E9E9),
	AESx(0x8749CECE), AESx(0xAAFF5555), AESx(0x50782828), AESx(0xA57ADFDF),
	AESx(0x038F8C8C), AESx(0x59F8A1A1), AESx(0x09808989), AESx(0x1A170D0D),
	AESx(0x65DABFBF), AESx(0xD731E6E6), AESx(0x84C64242), AESx(0xD0B86868),
	AESx(0x82C34141), AESx(0x29B09999), AESx(0x5A772D2D), AESx(0x1E110F0F),
	AESx(0x7BCBB0B0), AESx(0xA8FC5454), AESx(0x6DD6BBBB), AESx(0x2C3A1616)
};

#endif

/*-
 * Copyright 2009 Colin Percival, 2011 ArtForz, 2011 pooler, 2012 mtrlt,
 * 2012-2013 Con Kolivas, 2013 Alexey Karimov.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */

__constant uint ES[2] = { 0x00FF00FF, 0xFF00FF00 };
__constant uint K[] = {
	0x428a2f98U,
	0x71374491U,
	0xb5c0fbcfU,
	0xe9b5dba5U,
	0x3956c25bU,
	0x59f111f1U,
	0x923f82a4U,
	0xab1c5ed5U,
	0xd807aa98U,
	0x12835b01U,
	0x243185beU, // 10
	0x550c7dc3U,
	0x72be5d74U,
	0x80deb1feU,
	0x9bdc06a7U,
	0xe49b69c1U,
	0xefbe4786U,
	0x0fc19dc6U,
	0x240ca1ccU,
	0x2de92c6fU,
	0x4a7484aaU, // 20
	0x5cb0a9dcU,
	0x76f988daU,
	0x983e5152U,
	0xa831c66dU,
	0xb00327c8U,
	0xbf597fc7U,
	0xc6e00bf3U,
	0xd5a79147U,
	0x06ca6351U,
	0x14292967U, // 30
	0x27b70a85U,
	0x2e1b2138U,
	0x4d2c6dfcU,
	0x53380d13U,
	0x650a7354U,
	0x766a0abbU,
	0x81c2c92eU,
	0x92722c85U,
	0xa2bfe8a1U,
	0xa81a664bU, // 40
	0xc24b8b70U,
	0xc76c51a3U,
	0xd192e819U,
	0xd6990624U,
	0xf40e3585U,
	0x106aa070U,
	0x19a4c116U,
	0x1e376c08U,
	0x2748774cU,
	0x34b0bcb5U, // 50
	0x391c0cb3U,
	0x4ed8aa4aU,
	0x5b9cca4fU,
	0x682e6ff3U,
	0x748f82eeU,
	0x78a5636fU,
	0x84c87814U,
	0x8cc70208U,
	0x90befffaU,
	0xa4506cebU, // 60
	0xbef9a3f7U,
	0xc67178f2U,
	0x98c7e2a2U,
	0xfc08884dU,
	0xcd2a11aeU,
	0x510e527fU,
	0x9b05688cU,
	0xC3910C8EU,
	0xfb6feee7U,
	0x2a01a605U, // 70
	0x0c2e12e0U,
	0x4498517BU,
	0x6a09e667U,
	0xa4ce148bU,
	0x95F61999U,
	0xc19bf174U,
	0xBB67AE85U,
	0x3C6EF372U,
	0xA54FF53AU,
	0x1F83D9ABU, // 80
	0x5BE0CD19U,
	0x5C5C5C5CU,
	0x36363636U,
	0x80000000U,
	0x000003FFU,
	0x00000280U,
	0x000004a0U,
	0x00000300U
};

#define rotl(x,y) rotate(x,y)
#define Ch(x,y,z) bitselect(z,y,x)
#define Maj(x,y,z) Ch((x^z),y,z)

#define EndianSwap(n) (rotl(n & ES[0], 24U)|rotl(n & ES[1], 8U))

#define Tr2(x)		(rotl(x, 30U) ^ rotl(x, 19U) ^ rotl(x, 10U))
#define Tr1(x)		(rotl(x, 26U) ^ rotl(x, 21U) ^ rotl(x, 7U))
#define Wr2(x)		(rotl(x, 25U) ^ rotl(x, 14U) ^ (x>>3U))
#define Wr1(x)		(rotl(x, 15U) ^ rotl(x, 13U) ^ (x>>10U))

#define RND(a, b, c, d, e, f, g, h, k)	\
	h += Tr1(e); 			\
	h += Ch(e, f, g); 		\
	h += k;				\
	d += h;				\
	h += Tr2(a); 			\
	h += Maj(a, b, c);

void SHA256(uint4*restrict state0,uint4*restrict state1, const uint4 block0, const uint4 block1, const uint4 block2, const uint4 block3)
{
	uint4 S0 = *state0;
	uint4 S1 = *state1;
	
#define A S0.x
#define B S0.y
#define C S0.z
#define D S0.w
#define E S1.x
#define F S1.y
#define G S1.z
#define H S1.w

	uint4 W[4];

	W[ 0].x = block0.x;
	RND(A,B,C,D,E,F,G,H, W[0].x+ K[0]);
	W[ 0].y = block0.y;
	RND(H,A,B,C,D,E,F,G, W[0].y+ K[1]);
	W[ 0].z = block0.z;
	RND(G,H,A,B,C,D,E,F, W[0].z+ K[2]);
	W[ 0].w = block0.w;
	RND(F,G,H,A,B,C,D,E, W[0].w+ K[3]);

	W[ 1].x = block1.x;
	RND(E,F,G,H,A,B,C,D, W[1].x+ K[4]);
	W[ 1].y = block1.y;
	RND(D,E,F,G,H,A,B,C, W[1].y+ K[5]);
	W[ 1].z = block1.z;
	RND(C,D,E,F,G,H,A,B, W[1].z+ K[6]);
	W[ 1].w = block1.w;
	RND(B,C,D,E,F,G,H,A, W[1].w+ K[7]);

	W[ 2].x = block2.x;
	RND(A,B,C,D,E,F,G,H, W[2].x+ K[8]);
	W[ 2].y = block2.y;
	RND(H,A,B,C,D,E,F,G, W[2].y+ K[9]);
	W[ 2].z = block2.z;
	RND(G,H,A,B,C,D,E,F, W[2].z+ K[10]);
	W[ 2].w = block2.w;
	RND(F,G,H,A,B,C,D,E, W[2].w+ K[11]);

	W[ 3].x = block3.x;
	RND(E,F,G,H,A,B,C,D, W[3].x+ K[12]);
	W[ 3].y = block3.y;
	RND(D,E,F,G,H,A,B,C, W[3].y+ K[13]);
	W[ 3].z = block3.z;
	RND(C,D,E,F,G,H,A,B, W[3].z+ K[14]);
	W[ 3].w = block3.w;
	RND(B,C,D,E,F,G,H,A, W[3].w+ K[76]);

	W[ 0].x += Wr1(W[ 3].z) + W[ 2].y + Wr2(W[ 0].y);
	RND(A,B,C,D,E,F,G,H, W[0].x+ K[15]);

	W[ 0].y += Wr1(W[ 3].w) + W[ 2].z + Wr2(W[ 0].z);
	RND(H,A,B,C,D,E,F,G, W[0].y+ K[16]);

	W[ 0].z += Wr1(W[ 0].x) + W[ 2].w + Wr2(W[ 0].w);
	RND(G,H,A,B,C,D,E,F, W[0].z+ K[17]);

	W[ 0].w += Wr1(W[ 0].y) + W[ 3].x + Wr2(W[ 1].x);
	RND(F,G,H,A,B,C,D,E, W[0].w+ K[18]);

	W[ 1].x += Wr1(W[ 0].z) + W[ 3].y + Wr2(W[ 1].y);
	RND(E,F,G,H,A,B,C,D, W[1].x+ K[19]);

	W[ 1].y += Wr1(W[ 0].w) + W[ 3].z + Wr2(W[ 1].z);
	RND(D,E,F,G,H,A,B,C, W[1].y+ K[20]);

	W[ 1].z += Wr1(W[ 1].x) + W[ 3].w + Wr2(W[ 1].w);
	RND(C,D,E,F,G,H,A,B, W[1].z+ K[21]);

	W[ 1].w += Wr1(W[ 1].y) + W[ 0].x + Wr2(W[ 2].x);
	RND(B,C,D,E,F,G,H,A, W[1].w+ K[22]);

	W[ 2].x += Wr1(W[ 1].z) + W[ 0].y + Wr2(W[ 2].y);
	RND(A,B,C,D,E,F,G,H, W[2].x+ K[23]);

	W[ 2].y += Wr1(W[ 1].w) + W[ 0].z + Wr2(W[ 2].z);
	RND(H,A,B,C,D,E,F,G, W[2].y+ K[24]);

	W[ 2].z += Wr1(W[ 2].x) + W[ 0].w + Wr2(W[ 2].w);
	RND(G,H,A,B,C,D,E,F, W[2].z+ K[25]);

	W[ 2].w += Wr1(W[ 2].y) + W[ 1].x + Wr2(W[ 3].x);
	RND(F,G,H,A,B,C,D,E, W[2].w+ K[26]);

	W[ 3].x += Wr1(W[ 2].z) + W[ 1].y + Wr2(W[ 3].y);
	RND(E,F,G,H,A,B,C,D, W[3].x+ K[27]);

	W[ 3].y += Wr1(W[ 2].w) + W[ 1].z + Wr2(W[ 3].z);
	RND(D,E,F,G,H,A,B,C, W[3].y+ K[28]);

	W[ 3].z += Wr1(W[ 3].x) + W[ 1].w + Wr2(W[ 3].w);
	RND(C,D,E,F,G,H,A,B, W[3].z+ K[29]);

	W[ 3].w += Wr1(W[ 3].y) + W[ 2].x + Wr2(W[ 0].x);
	RND(B,C,D,E,F,G,H,A, W[3].w+ K[30]);

	W[ 0].x += Wr1(W[ 3].z) + W[ 2].y + Wr2(W[ 0].y);
	RND(A,B,C,D,E,F,G,H, W[0].x+ K[31]);

	W[ 0].y += Wr1(W[ 3].w) + W[ 2].z + Wr2(W[ 0].z);
	RND(H,A,B,C,D,E,F,G, W[0].y+ K[32]);

	W[ 0].z += Wr1(W[ 0].x) + W[ 2].w + Wr2(W[ 0].w);
	RND(G,H,A,B,C,D,E,F, W[0].z+ K[33]);

	W[ 0].w += Wr1(W[ 0].y) + W[ 3].x + Wr2(W[ 1].x);
	RND(F,G,H,A,B,C,D,E, W[0].w+ K[34]);

	W[ 1].x += Wr1(W[ 0].z) + W[ 3].y + Wr2(W[ 1].y);
	RND(E,F,G,H,A,B,C,D, W[1].x+ K[35]);

	W[ 1].y += Wr1(W[ 0].w) + W[ 3].z + Wr2(W[ 1].z);
	RND(D,E,F,G,H,A,B,C, W[1].y+ K[36]);

	W[ 1].z += Wr1(W[ 1].x) + W[ 3].w + Wr2(W[ 1].w);
	RND(C,D,E,F,G,H,A,B, W[1].z+ K[37]);

	W[ 1].w += Wr1(W[ 1].y) + W[ 0].x + Wr2(W[ 2].x);
	RND(B,C,D,E,F,G,H,A, W[1].w+ K[38]);

	W[ 2].x += Wr1(W[ 1].z) + W[ 0].y + Wr2(W[ 2].y);
	RND(A,B,C,D,E,F,G,H, W[2].x+ K[39]);

	W[ 2].y += Wr1(W[ 1].w) + W[ 0].z + Wr2(W[ 2].z);
	RND(H,A,B,C,D,E,F,G, W[2].y+ K[40]);

	W[ 2].z += Wr1(W[ 2].x) + W[ 0].w + Wr2(W[ 2].w);
	RND(G,H,A,B,C,D,E,F, W[2].z+ K[41]);

	W[ 2].w += Wr1(W[ 2].y) + W[ 1].x + Wr2(W[ 3].x);
	RND(F,G,H,A,B,C,D,E, W[2].w+ K[42]);

	W[ 3].x += Wr1(W[ 2].z) + W[ 1].y + Wr2(W[ 3].y);
	RND(E,F,G,H,A,B,C,D, W[3].x+ K[43]);

	W[ 3].y += Wr1(W[ 2].w) + W[ 1].z + Wr2(W[ 3].z);
	RND(D,E,F,G,H,A,B,C, W[3].y+ K[44]);

	W[ 3].z += Wr1(W[ 3].x) + W[ 1].w + Wr2(W[ 3].w);
	RND(C,D,E,F,G,H,A,B, W[3].z+ K[45]);

	W[ 3].w += Wr1(W[ 3].y) + W[ 2].x + Wr2(W[ 0].x);
	RND(B,C,D,E,F,G,H,A, W[3].w+ K[46]);

	W[ 0].x += Wr1(W[ 3].z) + W[ 2].y + Wr2(W[ 0].y);
	RND(A,B,C,D,E,F,G,H, W[0].x+ K[47]);

	W[ 0].y += Wr1(W[ 3].w) + W[ 2].z + Wr2(W[ 0].z);
	RND(H,A,B,C,D,E,F,G, W[0].y+ K[48]);

	W[ 0].z += Wr1(W[ 0].x) + W[ 2].w + Wr2(W[ 0].w);
	RND(G,H,A,B,C,D,E,F, W[0].z+ K[49]);

	W[ 0].w += Wr1(W[ 0].y) + W[ 3].x + Wr2(W[ 1].x);
	RND(F,G,H,A,B,C,D,E, W[0].w+ K[50]);

	W[ 1].x += Wr1(W[ 0].z) + W[ 3].y + Wr2(W[ 1].y);
	RND(E,F,G,H,A,B,C,D, W[1].x+ K[51]);

	W[ 1].y += Wr1(W[ 0].w) + W[ 3].z + Wr2(W[ 1].z);
	RND(D,E,F,G,H,A,B,C, W[1].y+ K[52]);

	W[ 1].z += Wr1(W[ 1].x) + W[ 3].w + Wr2(W[ 1].w);
	RND(C,D,E,F,G,H,A,B, W[1].z+ K[53]);

	W[ 1].w += Wr1(W[ 1].y) + W[ 0].x + Wr2(W[ 2].x);
	RND(B,C,D,E,F,G,H,A, W[1].w+ K[54]);

	W[ 2].x += Wr1(W[ 1].z) + W[ 0].y + Wr2(W[ 2].y);
	RND(A,B,C,D,E,F,G,H, W[2].x+ K[55]);

	W[ 2].y += Wr1(W[ 1].w) + W[ 0].z + Wr2(W[ 2].z);
	RND(H,A,B,C,D,E,F,G, W[2].y+ K[56]);

	W[ 2].z += Wr1(W[ 2].x) + W[ 0].w + Wr2(W[ 2].w);
	RND(G,H,A,B,C,D,E,F, W[2].z+ K[57]);

	W[ 2].w += Wr1(W[ 2].y) + W[ 1].x + Wr2(W[ 3].x);
	RND(F,G,H,A,B,C,D,E, W[2].w+ K[58]);

	W[ 3].x += Wr1(W[ 2].z) + W[ 1].y + Wr2(W[ 3].y);
	RND(E,F,G,H,A,B,C,D, W[3].x+ K[59]);

	W[ 3].y += Wr1(W[ 2].w) + W[ 1].z + Wr2(W[ 3].z);
	RND(D,E,F,G,H,A,B,C, W[3].y+ K[60]);

	W[ 3].z += Wr1(W[ 3].x) + W[ 1].w + Wr2(W[ 3].w);
	RND(C,D,E,F,G,H,A,B, W[3].z+ K[61]);

	W[ 3].w += Wr1(W[ 3].y) + W[ 2].x + Wr2(W[ 0].x);
	RND(B,C,D,E,F,G,H,A, W[3].w+ K[62]);
	
#undef A
#undef B
#undef C
#undef D
#undef E
#undef F
#undef G
#undef H

	*state0 += S0;
	*state1 += S1;
}

void SHA256_fresh(uint4*restrict state0,uint4*restrict state1, const uint4 block0, const uint4 block1, const uint4 block2, const uint4 block3)
{
#define A (*state0).x
#define B (*state0).y
#define C (*state0).z
#define D (*state0).w
#define E (*state1).x
#define F (*state1).y
#define G (*state1).z
#define H (*state1).w

	uint4 W[4];

	W[0].x = block0.x;
	D= K[63] +W[0].x;
	H= K[64] +W[0].x;

	W[0].y = block0.y;
	C= K[65] +Tr1(D)+Ch(D, K[66], K[67])+W[0].y;
	G= K[68] +C+Tr2(H)+Ch(H, K[69] ,K[70]);

	W[0].z = block0.z;
	B= K[71] +Tr1(C)+Ch(C,D,K[66])+W[0].z;
	F= K[72] +B+Tr2(G)+Maj(G,H, K[73]);

	W[0].w = block0.w;
	A= K[74] +Tr1(B)+Ch(B,C,D)+W[0].w;
	E= K[75] +A+Tr2(F)+Maj(F,G,H);

	W[1].x = block1.x;
	RND(E,F,G,H,A,B,C,D, W[1].x+ K[4]);
	W[1].y = block1.y;
	RND(D,E,F,G,H,A,B,C, W[1].y+ K[5]);
	W[1].z = block1.z;
	RND(C,D,E,F,G,H,A,B, W[1].z+ K[6]);
	W[1].w = block1.w;
	RND(B,C,D,E,F,G,H,A, W[1].w+ K[7]);
	
	W[2].x = block2.x;
	RND(A,B,C,D,E,F,G,H, W[2].x+ K[8]);
	W[2].y = block2.y;
	RND(H,A,B,C,D,E,F,G, W[2].y+ K[9]);
	W[2].z = block2.z;
	RND(G,H,A,B,C,D,E,F, W[2].z+ K[10]);
	W[2].w = block2.w;
	RND(F,G,H,A,B,C,D,E, W[2].w+ K[11]);
	
	W[3].x = block3.x;
	RND(E,F,G,H,A,B,C,D, W[3].x+ K[12]);
	W[3].y = block3.y;
	RND(D,E,F,G,H,A,B,C, W[3].y+ K[13]);
	W[3].z = block3.z;
	RND(C,D,E,F,G,H,A,B, W[3].z+ K[14]);
	W[3].w = block3.w;
	RND(B,C,D,E,F,G,H,A, W[3].w+ K[76]);

	W[0].x += Wr1(W[3].z) + W[2].y + Wr2(W[0].y);
	RND(A,B,C,D,E,F,G,H, W[0].x+ K[15]);

	W[0].y += Wr1(W[3].w) + W[2].z + Wr2(W[0].z);
	RND(H,A,B,C,D,E,F,G, W[0].y+ K[16]);

	W[0].z += Wr1(W[0].x) + W[2].w + Wr2(W[0].w);
	RND(G,H,A,B,C,D,E,F, W[0].z+ K[17]);

	W[0].w += Wr1(W[0].y) + W[3].x + Wr2(W[1].x);
	RND(F,G,H,A,B,C,D,E, W[0].w+ K[18]);

	W[1].x += Wr1(W[0].z) + W[3].y + Wr2(W[1].y);
	RND(E,F,G,H,A,B,C,D, W[1].x+ K[19]);

	W[1].y += Wr1(W[0].w) + W[3].z + Wr2(W[1].z);
	RND(D,E,F,G,H,A,B,C, W[1].y+ K[20]);

	W[1].z += Wr1(W[1].x) + W[3].w + Wr2(W[1].w);
	RND(C,D,E,F,G,H,A,B, W[1].z+ K[21]);

	W[1].w += Wr1(W[1].y) + W[0].x + Wr2(W[2].x);
	RND(B,C,D,E,F,G,H,A, W[1].w+ K[22]);

	W[2].x += Wr1(W[1].z) + W[0].y + Wr2(W[2].y);
	RND(A,B,C,D,E,F,G,H, W[2].x+ K[23]);

	W[2].y += Wr1(W[1].w) + W[0].z + Wr2(W[2].z);
	RND(H,A,B,C,D,E,F,G, W[2].y+ K[24]);

	W[2].z += Wr1(W[2].x) + W[0].w + Wr2(W[2].w);
	RND(G,H,A,B,C,D,E,F, W[2].z+ K[25]);

	W[2].w += Wr1(W[2].y) + W[1].x + Wr2(W[3].x);
	RND(F,G,H,A,B,C,D,E, W[2].w+ K[26]);

	W[3].x += Wr1(W[2].z) + W[1].y + Wr2(W[3].y);
	RND(E,F,G,H,A,B,C,D, W[3].x+ K[27]);

	W[3].y += Wr1(W[2].w) + W[1].z + Wr2(W[3].z);
	RND(D,E,F,G,H,A,B,C, W[3].y+ K[28]);

	W[3].z += Wr1(W[3].x) + W[1].w + Wr2(W[3].w);
	RND(C,D,E,F,G,H,A,B, W[3].z+ K[29]);

	W[3].w += Wr1(W[3].y) + W[2].x + Wr2(W[0].x);
	RND(B,C,D,E,F,G,H,A, W[3].w+ K[30]);

	W[0].x += Wr1(W[3].z) + W[2].y + Wr2(W[0].y);
	RND(A,B,C,D,E,F,G,H, W[0].x+ K[31]);

	W[0].y += Wr1(W[3].w) + W[2].z + Wr2(W[0].z);
	RND(H,A,B,C,D,E,F,G, W[0].y+ K[32]);

	W[0].z += Wr1(W[0].x) + W[2].w + Wr2(W[0].w);
	RND(G,H,A,B,C,D,E,F, W[0].z+ K[33]);

	W[0].w += Wr1(W[0].y) + W[3].x + Wr2(W[1].x);
	RND(F,G,H,A,B,C,D,E, W[0].w+ K[34]);

	W[1].x += Wr1(W[0].z) + W[3].y + Wr2(W[1].y);
	RND(E,F,G,H,A,B,C,D, W[1].x+ K[35]);

	W[1].y += Wr1(W[0].w) + W[3].z + Wr2(W[1].z);
	RND(D,E,F,G,H,A,B,C, W[1].y+ K[36]);

	W[1].z += Wr1(W[1].x) + W[3].w + Wr2(W[1].w);
	RND(C,D,E,F,G,H,A,B, W[1].z+ K[37]);

	W[1].w += Wr1(W[1].y) + W[0].x + Wr2(W[2].x);
	RND(B,C,D,E,F,G,H,A, W[1].w+ K[38]);

	W[2].x += Wr1(W[1].z) + W[0].y + Wr2(W[2].y);
	RND(A,B,C,D,E,F,G,H, W[2].x+ K[39]);

	W[2].y += Wr1(W[1].w) + W[0].z + Wr2(W[2].z);
	RND(H,A,B,C,D,E,F,G, W[2].y+ K[40]);

	W[2].z += Wr1(W[2].x) + W[0].w + Wr2(W[2].w);
	RND(G,H,A,B,C,D,E,F, W[2].z+ K[41]);

	W[2].w += Wr1(W[2].y) + W[1].x + Wr2(W[3].x);
	RND(F,G,H,A,B,C,D,E, W[2].w+ K[42]);

	W[3].x += Wr1(W[2].z) + W[1].y + Wr2(W[3].y);
	RND(E,F,G,H,A,B,C,D, W[3].x+ K[43]);

	W[3].y += Wr1(W[2].w) + W[1].z + Wr2(W[3].z);
	RND(D,E,F,G,H,A,B,C, W[3].y+ K[44]);

	W[3].z += Wr1(W[3].x) + W[1].w + Wr2(W[3].w);
	RND(C,D,E,F,G,H,A,B, W[3].z+ K[45]);

	W[3].w += Wr1(W[3].y) + W[2].x + Wr2(W[0].x);
	RND(B,C,D,E,F,G,H,A, W[3].w+ K[46]);

	W[0].x += Wr1(W[3].z) + W[2].y + Wr2(W[0].y);
	RND(A,B,C,D,E,F,G,H, W[0].x+ K[47]);

	W[0].y += Wr1(W[3].w) + W[2].z + Wr2(W[0].z);
	RND(H,A,B,C,D,E,F,G, W[0].y+ K[48]);

	W[0].z += Wr1(W[0].x) + W[2].w + Wr2(W[0].w);
	RND(G,H,A,B,C,D,E,F, W[0].z+ K[49]);

	W[0].w += Wr1(W[0].y) + W[3].x + Wr2(W[1].x);
	RND(F,G,H,A,B,C,D,E, W[0].w+ K[50]);

	W[1].x += Wr1(W[0].z) + W[3].y + Wr2(W[1].y);
	RND(E,F,G,H,A,B,C,D, W[1].x+ K[51]);

	W[1].y += Wr1(W[0].w) + W[3].z + Wr2(W[1].z);
	RND(D,E,F,G,H,A,B,C, W[1].y+ K[52]);

	W[1].z += Wr1(W[1].x) + W[3].w + Wr2(W[1].w);
	RND(C,D,E,F,G,H,A,B, W[1].z+ K[53]);

	W[1].w += Wr1(W[1].y) + W[0].x + Wr2(W[2].x);
	RND(B,C,D,E,F,G,H,A, W[1].w+ K[54]);

	W[2].x += Wr1(W[1].z) + W[0].y + Wr2(W[2].y);
	RND(A,B,C,D,E,F,G,H, W[2].x+ K[55]);

	W[2].y += Wr1(W[1].w) + W[0].z + Wr2(W[2].z);
	RND(H,A,B,C,D,E,F,G, W[2].y+ K[56]);

	W[2].z += Wr1(W[2].x) + W[0].w + Wr2(W[2].w);
	RND(G,H,A,B,C,D,E,F, W[2].z+ K[57]);

	W[2].w += Wr1(W[2].y) + W[1].x + Wr2(W[3].x);
	RND(F,G,H,A,B,C,D,E, W[2].w+ K[58]);

	W[3].x += Wr1(W[2].z) + W[1].y + Wr2(W[3].y);
	RND(E,F,G,H,A,B,C,D, W[3].x+ K[59]);

	W[3].y += Wr1(W[2].w) + W[1].z + Wr2(W[3].z);
	RND(D,E,F,G,H,A,B,C, W[3].y+ K[60]);

	W[3].z += Wr1(W[3].x) + W[1].w + Wr2(W[3].w);
	RND(C,D,E,F,G,H,A,B, W[3].z+ K[61]);

	W[3].w += Wr1(W[3].y) + W[2].x + Wr2(W[0].x);
	RND(B,C,D,E,F,G,H,A, W[3].w+ K[62]);
	
#undef A
#undef B
#undef C
#undef D
#undef E
#undef F
#undef G
#undef H

	*state0 += (uint4)(K[73], K[77], K[78], K[79]);
	*state1 += (uint4)(K[66], K[67], K[80], K[81]);
}

__constant uint fixedW[64] =
{
	0x428a2f99,0xf1374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf794,
	0xf59b89c2,0x73924787,0x23c6886e,0xa42ca65c,0x15ed3627,0x4d6edcbf,0xe28217fc,0xef02488f,
	0xb707775c,0x0468c23f,0xe7e72b4c,0x49e1f1a2,0x4b99c816,0x926d1570,0xaa0fc072,0xadb36e2c,
	0xad87a3ea,0xbcb1d3a3,0x7b993186,0x562b9420,0xbff3ca0c,0xda4b0c23,0x6cd8711a,0x8f337caa,
	0xc91b1417,0xc359dce1,0xa83253a7,0x3b13c12d,0x9d3d725d,0xd9031a84,0xb1a03340,0x16f58012,
	0xe64fb6a2,0xe84d923a,0xe93a5730,0x09837686,0x078ff753,0x29833341,0xd5de0b7e,0x6948ccf4,
	0xe0a1adbe,0x7c728e11,0x511c78e4,0x315b45bd,0xfca71413,0xea28f96a,0x79703128,0x4e1ef848,
};

void SHA256_fixed(uint4*restrict state0,uint4*restrict state1)
{
	uint4 S0 = *state0;
	uint4 S1 = *state1;

#define A S0.x
#define B S0.y
#define C S0.z
#define D S0.w
#define E S1.x
#define F S1.y
#define G S1.z
#define H S1.w

	RND(A,B,C,D,E,F,G,H, fixedW[0]);
	RND(H,A,B,C,D,E,F,G, fixedW[1]);
	RND(G,H,A,B,C,D,E,F, fixedW[2]);
	RND(F,G,H,A,B,C,D,E, fixedW[3]);
	RND(E,F,G,H,A,B,C,D, fixedW[4]);
	RND(D,E,F,G,H,A,B,C, fixedW[5]);
	RND(C,D,E,F,G,H,A,B, fixedW[6]);
	RND(B,C,D,E,F,G,H,A, fixedW[7]);
	RND(A,B,C,D,E,F,G,H, fixedW[8]);
	RND(H,A,B,C,D,E,F,G, fixedW[9]);
	RND(G,H,A,B,C,D,E,F, fixedW[10]);
	RND(F,G,H,A,B,C,D,E, fixedW[11]);
	RND(E,F,G,H,A,B,C,D, fixedW[12]);
	RND(D,E,F,G,H,A,B,C, fixedW[13]);
	RND(C,D,E,F,G,H,A,B, fixedW[14]);
	RND(B,C,D,E,F,G,H,A, fixedW[15]);
	RND(A,B,C,D,E,F,G,H, fixedW[16]);
	RND(H,A,B,C,D,E,F,G, fixedW[17]);
	RND(G,H,A,B,C,D,E,F, fixedW[18]);
	RND(F,G,H,A,B,C,D,E, fixedW[19]);
	RND(E,F,G,H,A,B,C,D, fixedW[20]);
	RND(D,E,F,G,H,A,B,C, fixedW[21]);
	RND(C,D,E,F,G,H,A,B, fixedW[22]);
	RND(B,C,D,E,F,G,H,A, fixedW[23]);
	RND(A,B,C,D,E,F,G,H, fixedW[24]);
	RND(H,A,B,C,D,E,F,G, fixedW[25]);
	RND(G,H,A,B,C,D,E,F, fixedW[26]);
	RND(F,G,H,A,B,C,D,E, fixedW[27]);
	RND(E,F,G,H,A,B,C,D, fixedW[28]);
	RND(D,E,F,G,H,A,B,C, fixedW[29]);
	RND(C,D,E,F,G,H,A,B, fixedW[30]);
	RND(B,C,D,E,F,G,H,A, fixedW[31]);
	RND(A,B,C,D,E,F,G,H, fixedW[32]);
	RND(H,A,B,C,D,E,F,G, fixedW[33]);
	RND(G,H,A,B,C,D,E,F, fixedW[34]);
	RND(F,G,H,A,B,C,D,E, fixedW[35]);
	RND(E,F,G,H,A,B,C,D, fixedW[36]);
	RND(D,E,F,G,H,A,B,C, fixedW[37]);
	RND(C,D,E,F,G,H,A,B, fixedW[38]);
	RND(B,C,D,E,F,G,H,A, fixedW[39]);
	RND(A,B,C,D,E,F,G,H, fixedW[40]);
	RND(H,A,B,C,D,E,F,G, fixedW[41]);
	RND(G,H,A,B,C,D,E,F, fixedW[42]);
	RND(F,G,H,A,B,C,D,E, fixedW[43]);
	RND(E,F,G,H,A,B,C,D, fixedW[44]);
	RND(D,E,F,G,H,A,B,C, fixedW[45]);
	RND(C,D,E,F,G,H,A,B, fixedW[46]);
	RND(B,C,D,E,F,G,H,A, fixedW[47]);
	RND(A,B,C,D,E,F,G,H, fixedW[48]);
	RND(H,A,B,C,D,E,F,G, fixedW[49]);
	RND(G,H,A,B,C,D,E,F, fixedW[50]);
	RND(F,G,H,A,B,C,D,E, fixedW[51]);
	RND(E,F,G,H,A,B,C,D, fixedW[52]);
	RND(D,E,F,G,H,A,B,C, fixedW[53]);
	RND(C,D,E,F,G,H,A,B, fixedW[54]);
	RND(B,C,D,E,F,G,H,A, fixedW[55]);
	RND(A,B,C,D,E,F,G,H, fixedW[56]);
	RND(H,A,B,C,D,E,F,G, fixedW[57]);
	RND(G,H,A,B,C,D,E,F, fixedW[58]);
	RND(F,G,H,A,B,C,D,E, fixedW[59]);
	RND(E,F,G,H,A,B,C,D, fixedW[60]);
	RND(D,E,F,G,H,A,B,C, fixedW[61]);
	RND(C,D,E,F,G,H,A,B, fixedW[62]);
	RND(B,C,D,E,F,G,H,A, fixedW[63]);
	
#undef A
#undef B
#undef C
#undef D
#undef E
#undef F
#undef G
#undef H
	*state0 += S0;
	*state1 += S1;
}

void shittify(uint4 B[8])
{
	uint4 tmp[4];
	tmp[0] = (uint4)(B[1].x,B[2].y,B[3].z,B[0].w);
	tmp[1] = (uint4)(B[2].x,B[3].y,B[0].z,B[1].w);
	tmp[2] = (uint4)(B[3].x,B[0].y,B[1].z,B[2].w);
	tmp[3] = (uint4)(B[0].x,B[1].y,B[2].z,B[3].w);
	
#pragma unroll
	for(uint i=0; i<4; ++i)
		B[i] = EndianSwap(tmp[i]);

	tmp[0] = (uint4)(B[5].x,B[6].y,B[7].z,B[4].w);
	tmp[1] = (uint4)(B[6].x,B[7].y,B[4].z,B[5].w);
	tmp[2] = (uint4)(B[7].x,B[4].y,B[5].z,B[6].w);
	tmp[3] = (uint4)(B[4].x,B[5].y,B[6].z,B[7].w);
	
#pragma unroll
	for(uint i=0; i<4; ++i)
		B[i+4] = EndianSwap(tmp[i]);
}

void unshittify(uint4 B[8])
{
	uint4 tmp[4];
	tmp[0] = (uint4)(B[3].x,B[2].y,B[1].z,B[0].w);
	tmp[1] = (uint4)(B[0].x,B[3].y,B[2].z,B[1].w);
	tmp[2] = (uint4)(B[1].x,B[0].y,B[3].z,B[2].w);
	tmp[3] = (uint4)(B[2].x,B[1].y,B[0].z,B[3].w);
	
#pragma unroll
	for(uint i=0; i<4; ++i)
		B[i] = EndianSwap(tmp[i]);

	tmp[0] = (uint4)(B[7].x,B[6].y,B[5].z,B[4].w);
	tmp[1] = (uint4)(B[4].x,B[7].y,B[6].z,B[5].w);
	tmp[2] = (uint4)(B[5].x,B[4].y,B[7].z,B[6].w);
	tmp[3] = (uint4)(B[6].x,B[5].y,B[4].z,B[7].w);
	
#pragma unroll
	for(uint i=0; i<4; ++i)
		B[i+4] = EndianSwap(tmp[i]);
}

void salsa(uint4 B[8])
{
	uint4 w[4];

#pragma unroll
	for(uint i=0; i<4; ++i)
		w[i] = (B[i]^=B[i+4]);

#pragma unroll
	for(uint i=0; i<4; ++i)
	{
		w[0] ^= rotl(w[3]     +w[2]     , 7U);
		w[1] ^= rotl(w[0]     +w[3]     , 9U);
		w[2] ^= rotl(w[1]     +w[0]     ,13U);
		w[3] ^= rotl(w[2]     +w[1]     ,18U);
		w[2] ^= rotl(w[3].wxyz+w[0].zwxy, 7U);
		w[1] ^= rotl(w[2].wxyz+w[3].zwxy, 9U);
		w[0] ^= rotl(w[1].wxyz+w[2].zwxy,13U);
		w[3] ^= rotl(w[0].wxyz+w[1].zwxy,18U);
	}

#pragma unroll
	for(uint i=0; i<4; ++i)
		w[i] = (B[i+4]^=(B[i]+=w[i]));

#pragma unroll
	for(uint i=0; i<4; ++i)
	{
		w[0] ^= rotl(w[3]     +w[2]     , 7U);
		w[1] ^= rotl(w[0]     +w[3]     , 9U);
		w[2] ^= rotl(w[1]     +w[0]     ,13U);
		w[3] ^= rotl(w[2]     +w[1]     ,18U);
		w[2] ^= rotl(w[3].wxyz+w[0].zwxy, 7U);
		w[1] ^= rotl(w[2].wxyz+w[3].zwxy, 9U);
		w[0] ^= rotl(w[1].wxyz+w[2].zwxy,13U);
		w[3] ^= rotl(w[0].wxyz+w[1].zwxy,18U);
	}

#pragma unroll
	for(uint i=0; i<4; ++i)
		B[i+4] += w[i];
}

void scrypt_core(uint4 X[8], __global uint4*restrict lookup)
{
	shittify(X);
	const uint zSIZE = 8;
	const uint xSIZE = CONCURRENT_THREADS;
	uint x = get_global_id(0)%xSIZE;
	uint CO=rotl(x,3U);
	uint CO_tmp=rotl(xSIZE,3U);

	for(uint y=0; y<1024/LOOKUP_GAP; ++y, CO+=CO_tmp)
	{
		uint CO_reg=CO;
#pragma unroll
		for(uint z=0; z<zSIZE; ++z, ++CO_reg)
			lookup[CO_reg] = X[z];
		for(uint i=0; i<LOOKUP_GAP; ++i) 
			salsa(X);
	}

	CO_tmp=rotl(x,3U);

#if (LOOKUP_GAP != 1) && (LOOKUP_GAP != 2) && (LOOKUP_GAP != 4) && (LOOKUP_GAP != 8)
	{
		uint y = (1024/LOOKUP_GAP);
		CO=CO_tmp+rotl(y*xSIZE,3U);
#pragma unroll
		for(uint z=0; z<zSIZE; ++z, ++CO)
			lookup[CO] = X[z];
		for(uint i=0; i<1024%LOOKUP_GAP; ++i)
			salsa(X); 
	}
#endif

	for (uint i=0; i<1024; ++i) 
	{
		uint4 V[8];
		uint j = X[7].x & K[85];
		uint y = (j/LOOKUP_GAP);
		uint CO_reg=CO_tmp+rotl(xSIZE*y,3U);

		for(uint z=0; z<zSIZE; ++z, ++CO_reg)
			V[z] = lookup[CO_reg];

#if (LOOKUP_GAP == 1)
#elif (LOOKUP_GAP == 2)
		if (j&1)
			salsa(V);
#else
		uint val = j%LOOKUP_GAP;
		for (uint z=0; z<val; ++z) 
			salsa(V);
#endif

#pragma unroll
		for(uint z=0; z<zSIZE; ++z)
			X[z] ^= V[z];
		salsa(X);
	}
	unshittify(X);
}

#define FOUND (0xFF)
#define SETFOUND(Xnonce) output[output[FOUND]++] = Xnonce

__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
__kernel void search(__global const uint4 * restrict input,
volatile __global uint*restrict output, __global uint4*restrict padcache,
const uint4 midstate0, const uint4 midstate16, const uint target)
{
	uint gid = get_global_id(0);
	uint4 X[8];
	uint4 tstate0, tstate1, ostate0, ostate1, tmp0, tmp1;
	uint4 data = (uint4)(input[4].x,input[4].y,input[4].z,gid);
	uint4 pad0 = midstate0, pad1 = midstate16;

	SHA256(&pad0,&pad1, data, (uint4)(K[84],0,0,0), (uint4)(0,0,0,0), (uint4)(0,0,0, K[86]));
	SHA256_fresh(&ostate0,&ostate1, pad0^ K[82], pad1^ K[82], K[82], K[82]);
	SHA256_fresh(&tstate0,&tstate1, pad0^ K[83], pad1^ K[83], K[83], K[83]);

	tmp0 = tstate0;
	tmp1 = tstate1;
	SHA256(&tstate0, &tstate1, input[0],input[1],input[2],input[3]);

#pragma unroll
	for (uint i=0; i<4; i++) 
	{
		pad0 = tstate0;
		pad1 = tstate1;
		X[rotl(i,1U) ] = ostate0;
		X[rotl(i,1U)+1] = ostate1;

		SHA256(&pad0,&pad1, data, (uint4)(i+1,K[84],0,0), (uint4)(0,0,0,0), (uint4)(0,0,0, K[87]));
		SHA256(X+rotl(i,1U),X+rotl(i,1U)+1, pad0, pad1, (uint4)(K[84], 0U, 0U, 0U), (uint4)(0U, 0U, 0U, K[88]));
	}
	scrypt_core(X,padcache);
	SHA256(&tmp0,&tmp1, X[0], X[1], X[2], X[3]);
	SHA256(&tmp0,&tmp1, X[4], X[5], X[6], X[7]);
	SHA256_fixed(&tmp0,&tmp1);
	SHA256(&ostate0,&ostate1, tmp0, tmp1, (uint4)(K[84], 0U, 0U, 0U), (uint4)(0U, 0U, 0U, K[88]));

	bool result = (EndianSwap(ostate1.w) <= target);
	if (result)
		SETFOUND(gid);
}

/*-
 * Copyright 2009 Colin Percival, 2011 ArtForz, 2011 pooler, 2012 mtrlt,
 * 2012-2013 Con Kolivas, 2013 Alexey Karimov.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */

__constant uint ES[2] = { 0x00FF00FF, 0xFF00FF00 };
__constant uint K[] = {
	0x428a2f98U,
	0x71374491U,
	0xb5c0fbcfU,
	0xe9b5dba5U,
	0x3956c25bU,
	0x59f111f1U,
	0x923f82a4U,
	0xab1c5ed5U,
	0xd807aa98U,
	0x12835b01U,
	0x243185beU, // 10
	0x550c7dc3U,
	0x72be5d74U,
	0x80deb1feU,
	0x9bdc06a7U,
	0xe49b69c1U,
	0xefbe4786U,
	0x0fc19dc6U,
	0x240ca1ccU,
	0x2de92c6fU,
	0x4a7484aaU, // 20
	0x5cb0a9dcU,
	0x76f988daU,
	0x983e5152U,
	0xa831c66dU,
	0xb00327c8U,
	0xbf597fc7U,
	0xc6e00bf3U,
	0xd5a79147U,
	0x06ca6351U,
	0x14292967U, // 30
	0x27b70a85U,
	0x2e1b2138U,
	0x4d2c6dfcU,
	0x53380d13U,
	0x650a7354U,
	0x766a0abbU,
	0x81c2c92eU,
	0x92722c85U,
	0xa2bfe8a1U,
	0xa81a664bU, // 40
	0xc24b8b70U,
	0xc76c51a3U,
	0xd192e819U,
	0xd6990624U,
	0xf40e3585U,
	0x106aa070U,
	0x19a4c116U,
	0x1e376c08U,
	0x2748774cU,
	0x34b0bcb5U, // 50
	0x391c0cb3U,
	0x4ed8aa4aU,
	0x5b9cca4fU,
	0x682e6ff3U,
	0x748f82eeU,
	0x78a5636fU,
	0x84c87814U,
	0x8cc70208U,
	0x90befffaU,
	0xa4506cebU, // 60
	0xbef9a3f7U,
	0xc67178f2U,
	0x98c7e2a2U,
	0xfc08884dU,
	0xcd2a11aeU,
	0x510e527fU,
	0x9b05688cU,
	0xC3910C8EU,
	0xfb6feee7U,
	0x2a01a605U, // 70
	0x0c2e12e0U,
	0x4498517BU,
	0x6a09e667U,
	0xa4ce148bU,
	0x95F61999U,
	0xc19bf174U,
	0xBB67AE85U,
	0x3C6EF372U,
	0xA54FF53AU,
	0x1F83D9ABU, // 80
	0x5BE0CD19U,
	0x5C5C5C5CU,
	0x36363636U,
	0x80000000U,
	0x000003FFU,
	0x00000280U,
	0x000004a0U,
	0x00000300U
};

#define rotl(x,y) rotate(x,y)
#define Ch(x,y,z) bitselect(z,y,x)
#define Maj(x,y,z) Ch((x^z),y,z)

#define EndianSwap(n) (rotl(n & ES[0], 24U)|rotl(n & ES[1], 8U))

#define Tr2(x)		(rotl(x, 30U) ^ rotl(x, 19U) ^ rotl(x, 10U))
#define Tr1(x)		(rotl(x, 26U) ^ rotl(x, 21U) ^ rotl(x, 7U))
#define Wr2(x)		(rotl(x, 25U) ^ rotl(x, 14U) ^ (x>>3U))
#define Wr1(x)		(rotl(x, 15U) ^ rotl(x, 13U) ^ (x>>10U))

#define RND(a, b, c, d, e, f, g, h, k)	\
	h += Tr1(e); 			\
	h += Ch(e, f, g); 		\
	h += k;				\
	d += h;				\
	h += Tr2(a); 			\
	h += Maj(a, b, c);

void SHA256(uint4*restrict state0,uint4*restrict state1, const uint4 block0, const uint4 block1, const uint4 block2, const uint4 block3)
{
	uint4 S0 = *state0;
	uint4 S1 = *state1;
	
#define A S0.x
#define B S0.y
#define C S0.z
#define D S0.w
#define E S1.x
#define F S1.y
#define G S1.z
#define H S1.w

	uint4 W[4];

	W[ 0].x = block0.x;
	RND(A,B,C,D,E,F,G,H, W[0].x+ K[0]);
	W[ 0].y = block0.y;
	RND(H,A,B,C,D,E,F,G, W[0].y+ K[1]);
	W[ 0].z = block0.z;
	RND(G,H,A,B,C,D,E,F, W[0].z+ K[2]);
	W[ 0].w = block0.w;
	RND(F,G,H,A,B,C,D,E, W[0].w+ K[3]);

	W[ 1].x = block1.x;
	RND(E,F,G,H,A,B,C,D, W[1].x+ K[4]);
	W[ 1].y = block1.y;
	RND(D,E,F,G,H,A,B,C, W[1].y+ K[5]);
	W[ 1].z = block1.z;
	RND(C,D,E,F,G,H,A,B, W[1].z+ K[6]);
	W[ 1].w = block1.w;
	RND(B,C,D,E,F,G,H,A, W[1].w+ K[7]);

	W[ 2].x = block2.x;
	RND(A,B,C,D,E,F,G,H, W[2].x+ K[8]);
	W[ 2].y = block2.y;
	RND(H,A,B,C,D,E,F,G, W[2].y+ K[9]);
	W[ 2].z = block2.z;
	RND(G,H,A,B,C,D,E,F, W[2].z+ K[10]);
	W[ 2].w = block2.w;
	RND(F,G,H,A,B,C,D,E, W[2].w+ K[11]);

	W[ 3].x = block3.x;
	RND(E,F,G,H,A,B,C,D, W[3].x+ K[12]);
	W[ 3].y = block3.y;
	RND(D,E,F,G,H,A,B,C, W[3].y+ K[13]);
	W[ 3].z = block3.z;
	RND(C,D,E,F,G,H,A,B, W[3].z+ K[14]);
	W[ 3].w = block3.w;
	RND(B,C,D,E,F,G,H,A, W[3].w+ K[76]);

	W[ 0].x += Wr1(W[ 3].z) + W[ 2].y + Wr2(W[ 0].y);
	RND(A,B,C,D,E,F,G,H, W[0].x+ K[15]);

	W[ 0].y += Wr1(W[ 3].w) + W[ 2].z + Wr2(W[ 0].z);
	RND(H,A,B,C,D,E,F,G, W[0].y+ K[16]);

	W[ 0].z += Wr1(W[ 0].x) + W[ 2].w + Wr2(W[ 0].w);
	RND(G,H,A,B,C,D,E,F, W[0].z+ K[17]);

	W[ 0].w += Wr1(W[ 0].y) + W[ 3].x + Wr2(W[ 1].x);
	RND(F,G,H,A,B,C,D,E, W[0].w+ K[18]);

	W[ 1].x += Wr1(W[ 0].z) + W[ 3].y + Wr2(W[ 1].y);
	RND(E,F,G,H,A,B,C,D, W[1].x+ K[19]);

	W[ 1].y += Wr1(W[ 0].w) + W[ 3].z + Wr2(W[ 1].z);
	RND(D,E,F,G,H,A,B,C, W[1].y+ K[20]);

	W[ 1].z += Wr1(W[ 1].x) + W[ 3].w + Wr2(W[ 1].w);
	RND(C,D,E,F,G,H,A,B, W[1].z+ K[21]);

	W[ 1].w += Wr1(W[ 1].y) + W[ 0].x + Wr2(W[ 2].x);
	RND(B,C,D,E,F,G,H,A, W[1].w+ K[22]);

	W[ 2].x += Wr1(W[ 1].z) + W[ 0].y + Wr2(W[ 2].y);
	RND(A,B,C,D,E,F,G,H, W[2].x+ K[23]);

	W[ 2].y += Wr1(W[ 1].w) + W[ 0].z + Wr2(W[ 2].z);
	RND(H,A,B,C,D,E,F,G, W[2].y+ K[24]);

	W[ 2].z += Wr1(W[ 2].x) + W[ 0].w + Wr2(W[ 2].w);
	RND(G,H,A,B,C,D,E,F, W[2].z+ K[25]);

	W[ 2].w += Wr1(W[ 2].y) + W[ 1].x + Wr2(W[ 3].x);
	RND(F,G,H,A,B,C,D,E, W[2].w+ K[26]);

	W[ 3].x += Wr1(W[ 2].z) + W[ 1].y + Wr2(W[ 3].y);
	RND(E,F,G,H,A,B,C,D, W[3].x+ K[27]);

	W[ 3].y += Wr1(W[ 2].w) + W[ 1].z + Wr2(W[ 3].z);
	RND(D,E,F,G,H,A,B,C, W[3].y+ K[28]);

	W[ 3].z += Wr1(W[ 3].x) + W[ 1].w + Wr2(W[ 3].w);
	RND(C,D,E,F,G,H,A,B, W[3].z+ K[29]);

	W[ 3].w += Wr1(W[ 3].y) + W[ 2].x + Wr2(W[ 0].x);
	RND(B,C,D,E,F,G,H,A, W[3].w+ K[30]);

	W[ 0].x += Wr1(W[ 3].z) + W[ 2].y + Wr2(W[ 0].y);
	RND(A,B,C,D,E,F,G,H, W[0].x+ K[31]);

	W[ 0].y += Wr1(W[ 3].w) + W[ 2].z + Wr2(W[ 0].z);
	RND(H,A,B,C,D,E,F,G, W[0].y+ K[32]);

	W[ 0].z += Wr1(W[ 0].x) + W[ 2].w + Wr2(W[ 0].w);
	RND(G,H,A,B,C,D,E,F, W[0].z+ K[33]);

	W[ 0].w += Wr1(W[ 0].y) + W[ 3].x + Wr2(W[ 1].x);
	RND(F,G,H,A,B,C,D,E, W[0].w+ K[34]);

	W[ 1].x += Wr1(W[ 0].z) + W[ 3].y + Wr2(W[ 1].y);
	RND(E,F,G,H,A,B,C,D, W[1].x+ K[35]);

	W[ 1].y += Wr1(W[ 0].w) + W[ 3].z + Wr2(W[ 1].z);
	RND(D,E,F,G,H,A,B,C, W[1].y+ K[36]);

	W[ 1].z += Wr1(W[ 1].x) + W[ 3].w + Wr2(W[ 1].w);
	RND(C,D,E,F,G,H,A,B, W[1].z+ K[37]);

	W[ 1].w += Wr1(W[ 1].y) + W[ 0].x + Wr2(W[ 2].x);
	RND(B,C,D,E,F,G,H,A, W[1].w+ K[38]);

	W[ 2].x += Wr1(W[ 1].z) + W[ 0].y + Wr2(W[ 2].y);
	RND(A,B,C,D,E,F,G,H, W[2].x+ K[39]);

	W[ 2].y += Wr1(W[ 1].w) + W[ 0].z + Wr2(W[ 2].z);
	RND(H,A,B,C,D,E,F,G, W[2].y+ K[40]);

	W[ 2].z += Wr1(W[ 2].x) + W[ 0].w + Wr2(W[ 2].w);
	RND(G,H,A,B,C,D,E,F, W[2].z+ K[41]);

	W[ 2].w += Wr1(W[ 2].y) + W[ 1].x + Wr2(W[ 3].x);
	RND(F,G,H,A,B,C,D,E, W[2].w+ K[42]);

	W[ 3].x += Wr1(W[ 2].z) + W[ 1].y + Wr2(W[ 3].y);
	RND(E,F,G,H,A,B,C,D, W[3].x+ K[43]);

	W[ 3].y += Wr1(W[ 2].w) + W[ 1].z + Wr2(W[ 3].z);
	RND(D,E,F,G,H,A,B,C, W[3].y+ K[44]);

	W[ 3].z += Wr1(W[ 3].x) + W[ 1].w + Wr2(W[ 3].w);
	RND(C,D,E,F,G,H,A,B, W[3].z+ K[45]);

	W[ 3].w += Wr1(W[ 3].y) + W[ 2].x + Wr2(W[ 0].x);
	RND(B,C,D,E,F,G,H,A, W[3].w+ K[46]);

	W[ 0].x += Wr1(W[ 3].z) + W[ 2].y + Wr2(W[ 0].y);
	RND(A,B,C,D,E,F,G,H, W[0].x+ K[47]);

	W[ 0].y += Wr1(W[ 3].w) + W[ 2].z + Wr2(W[ 0].z);
	RND(H,A,B,C,D,E,F,G, W[0].y+ K[48]);

	W[ 0].z += Wr1(W[ 0].x) + W[ 2].w + Wr2(W[ 0].w);
	RND(G,H,A,B,C,D,E,F, W[0].z+ K[49]);

	W[ 0].w += Wr1(W[ 0].y) + W[ 3].x + Wr2(W[ 1].x);
	RND(F,G,H,A,B,C,D,E, W[0].w+ K[50]);

	W[ 1].x += Wr1(W[ 0].z) + W[ 3].y + Wr2(W[ 1].y);
	RND(E,F,G,H,A,B,C,D, W[1].x+ K[51]);

	W[ 1].y += Wr1(W[ 0].w) + W[ 3].z + Wr2(W[ 1].z);
	RND(D,E,F,G,H,A,B,C, W[1].y+ K[52]);

	W[ 1].z += Wr1(W[ 1].x) + W[ 3].w + Wr2(W[ 1].w);
	RND(C,D,E,F,G,H,A,B, W[1].z+ K[53]);

	W[ 1].w += Wr1(W[ 1].y) + W[ 0].x + Wr2(W[ 2].x);
	RND(B,C,D,E,F,G,H,A, W[1].w+ K[54]);

	W[ 2].x += Wr1(W[ 1].z) + W[ 0].y + Wr2(W[ 2].y);
	RND(A,B,C,D,E,F,G,H, W[2].x+ K[55]);

	W[ 2].y += Wr1(W[ 1].w) + W[ 0].z + Wr2(W[ 2].z);
	RND(H,A,B,C,D,E,F,G, W[2].y+ K[56]);

	W[ 2].z += Wr1(W[ 2].x) + W[ 0].w + Wr2(W[ 2].w);
	RND(G,H,A,B,C,D,E,F, W[2].z+ K[57]);

	W[ 2].w += Wr1(W[ 2].y) + W[ 1].x + Wr2(W[ 3].x);
	RND(F,G,H,A,B,C,D,E, W[2].w+ K[58]);

	W[ 3].x += Wr1(W[ 2].z) + W[ 1].y + Wr2(W[ 3].y);
	RND(E,F,G,H,A,B,C,D, W[3].x+ K[59]);

	W[ 3].y += Wr1(W[ 2].w) + W[ 1].z + Wr2(W[ 3].z);
	RND(D,E,F,G,H,A,B,C, W[3].y+ K[60]);

	W[ 3].z += Wr1(W[ 3].x) + W[ 1].w + Wr2(W[ 3].w);
	RND(C,D,E,F,G,H,A,B, W[3].z+ K[61]);

	W[ 3].w += Wr1(W[ 3].y) + W[ 2].x + Wr2(W[ 0].x);
	RND(B,C,D,E,F,G,H,A, W[3].w+ K[62]);
	
#undef A
#undef B
#undef C
#undef D
#undef E
#undef F
#undef G
#undef H

	*state0 += S0;
	*state1 += S1;
}

void SHA256_fresh(uint4*restrict state0,uint4*restrict state1, const uint4 block0, const uint4 block1, const uint4 block2, const uint4 block3)
{
#define A (*state0).x
#define B (*state0).y
#define C (*state0).z
#define D (*state0).w
#define E (*state1).x
#define F (*state1).y
#define G (*state1).z
#define H (*state1).w

	uint4 W[4];

	W[0].x = block0.x;
	D= K[63] +W[0].x;
	H= K[64] +W[0].x;

	W[0].y = block0.y;
	C= K[65] +Tr1(D)+Ch(D, K[66], K[67])+W[0].y;
	G= K[68] +C+Tr2(H)+Ch(H, K[69] ,K[70]);

	W[0].z = block0.z;
	B= K[71] +Tr1(C)+Ch(C,D,K[66])+W[0].z;
	F= K[72] +B+Tr2(G)+Maj(G,H, K[73]);

	W[0].w = block0.w;
	A= K[74] +Tr1(B)+Ch(B,C,D)+W[0].w;
	E= K[75] +A+Tr2(F)+Maj(F,G,H);

	W[1].x = block1.x;
	RND(E,F,G,H,A,B,C,D, W[1].x+ K[4]);
	W[1].y = block1.y;
	RND(D,E,F,G,H,A,B,C, W[1].y+ K[5]);
	W[1].z = block1.z;
	RND(C,D,E,F,G,H,A,B, W[1].z+ K[6]);
	W[1].w = block1.w;
	RND(B,C,D,E,F,G,H,A, W[1].w+ K[7]);
	
	W[2].x = block2.x;
	RND(A,B,C,D,E,F,G,H, W[2].x+ K[8]);
	W[2].y = block2.y;
	RND(H,A,B,C,D,E,F,G, W[2].y+ K[9]);
	W[2].z = block2.z;
	RND(G,H,A,B,C,D,E,F, W[2].z+ K[10]);
	W[2].w = block2.w;
	RND(F,G,H,A,B,C,D,E, W[2].w+ K[11]);
	
	W[3].x = block3.x;
	RND(E,F,G,H,A,B,C,D, W[3].x+ K[12]);
	W[3].y = block3.y;
	RND(D,E,F,G,H,A,B,C, W[3].y+ K[13]);
	W[3].z = block3.z;
	RND(C,D,E,F,G,H,A,B, W[3].z+ K[14]);
	W[3].w = block3.w;
	RND(B,C,D,E,F,G,H,A, W[3].w+ K[76]);

	W[0].x += Wr1(W[3].z) + W[2].y + Wr2(W[0].y);
	RND(A,B,C,D,E,F,G,H, W[0].x+ K[15]);

	W[0].y += Wr1(W[3].w) + W[2].z + Wr2(W[0].z);
	RND(H,A,B,C,D,E,F,G, W[0].y+ K[16]);

	W[0].z += Wr1(W[0].x) + W[2].w + Wr2(W[0].w);
	RND(G,H,A,B,C,D,E,F, W[0].z+ K[17]);

	W[0].w += Wr1(W[0].y) + W[3].x + Wr2(W[1].x);
	RND(F,G,H,A,B,C,D,E, W[0].w+ K[18]);

	W[1].x += Wr1(W[0].z) + W[3].y + Wr2(W[1].y);
	RND(E,F,G,H,A,B,C,D, W[1].x+ K[19]);

	W[1].y += Wr1(W[0].w) + W[3].z + Wr2(W[1].z);
	RND(D,E,F,G,H,A,B,C, W[1].y+ K[20]);

	W[1].z += Wr1(W[1].x) + W[3].w + Wr2(W[1].w);
	RND(C,D,E,F,G,H,A,B, W[1].z+ K[21]);

	W[1].w += Wr1(W[1].y) + W[0].x + Wr2(W[2].x);
	RND(B,C,D,E,F,G,H,A, W[1].w+ K[22]);

	W[2].x += Wr1(W[1].z) + W[0].y + Wr2(W[2].y);
	RND(A,B,C,D,E,F,G,H, W[2].x+ K[23]);

	W[2].y += Wr1(W[1].w) + W[0].z + Wr2(W[2].z);
	RND(H,A,B,C,D,E,F,G, W[2].y+ K[24]);

	W[2].z += Wr1(W[2].x) + W[0].w + Wr2(W[2].w);
	RND(G,H,A,B,C,D,E,F, W[2].z+ K[25]);

	W[2].w += Wr1(W[2].y) + W[1].x + Wr2(W[3].x);
	RND(F,G,H,A,B,C,D,E, W[2].w+ K[26]);

	W[3].x += Wr1(W[2].z) + W[1].y + Wr2(W[3].y);
	RND(E,F,G,H,A,B,C,D, W[3].x+ K[27]);

	W[3].y += Wr1(W[2].w) + W[1].z + Wr2(W[3].z);
	RND(D,E,F,G,H,A,B,C, W[3].y+ K[28]);

	W[3].z += Wr1(W[3].x) + W[1].w + Wr2(W[3].w);
	RND(C,D,E,F,G,H,A,B, W[3].z+ K[29]);

	W[3].w += Wr1(W[3].y) + W[2].x + Wr2(W[0].x);
	RND(B,C,D,E,F,G,H,A, W[3].w+ K[30]);

	W[0].x += Wr1(W[3].z) + W[2].y + Wr2(W[0].y);
	RND(A,B,C,D,E,F,G,H, W[0].x+ K[31]);

	W[0].y += Wr1(W[3].w) + W[2].z + Wr2(W[0].z);
	RND(H,A,B,C,D,E,F,G, W[0].y+ K[32]);

	W[0].z += Wr1(W[0].x) + W[2].w + Wr2(W[0].w);
	RND(G,H,A,B,C,D,E,F, W[0].z+ K[33]);

	W[0].w += Wr1(W[0].y) + W[3].x + Wr2(W[1].x);
	RND(F,G,H,A,B,C,D,E, W[0].w+ K[34]);

	W[1].x += Wr1(W[0].z) + W[3].y + Wr2(W[1].y);
	RND(E,F,G,H,A,B,C,D, W[1].x+ K[35]);

	W[1].y += Wr1(W[0].w) + W[3].z + Wr2(W[1].z);
	RND(D,E,F,G,H,A,B,C, W[1].y+ K[36]);

	W[1].z += Wr1(W[1].x) + W[3].w + Wr2(W[1].w);
	RND(C,D,E,F,G,H,A,B, W[1].z+ K[37]);

	W[1].w += Wr1(W[1].y) + W[0].x + Wr2(W[2].x);
	RND(B,C,D,E,F,G,H,A, W[1].w+ K[38]);

	W[2].x += Wr1(W[1].z) + W[0].y + Wr2(W[2].y);
	RND(A,B,C,D,E,F,G,H, W[2].x+ K[39]);

	W[2].y += Wr1(W[1].w) + W[0].z + Wr2(W[2].z);
	RND(H,A,B,C,D,E,F,G, W[2].y+ K[40]);

	W[2].z += Wr1(W[2].x) + W[0].w + Wr2(W[2].w);
	RND(G,H,A,B,C,D,E,F, W[2].z+ K[41]);

	W[2].w += Wr1(W[2].y) + W[1].x + Wr2(W[3].x);
	RND(F,G,H,A,B,C,D,E, W[2].w+ K[42]);

	W[3].x += Wr1(W[2].z) + W[1].y + Wr2(W[3].y);
	RND(E,F,G,H,A,B,C,D, W[3].x+ K[43]);

	W[3].y += Wr1(W[2].w) + W[1].z + Wr2(W[3].z);
	RND(D,E,F,G,H,A,B,C, W[3].y+ K[44]);

	W[3].z += Wr1(W[3].x) + W[1].w + Wr2(W[3].w);
	RND(C,D,E,F,G,H,A,B, W[3].z+ K[45]);

	W[3].w += Wr1(W[3].y) + W[2].x + Wr2(W[0].x);
	RND(B,C,D,E,F,G,H,A, W[3].w+ K[46]);

	W[0].x += Wr1(W[3].z) + W[2].y + Wr2(W[0].y);
	RND(A,B,C,D,E,F,G,H, W[0].x+ K[47]);

	W[0].y += Wr1(W[3].w) + W[2].z + Wr2(W[0].z);
	RND(H,A,B,C,D,E,F,G, W[0].y+ K[48]);

	W[0].z += Wr1(W[0].x) + W[2].w + Wr2(W[0].w);
	RND(G,H,A,B,C,D,E,F, W[0].z+ K[49]);

	W[0].w += Wr1(W[0].y) + W[3].x + Wr2(W[1].x);
	RND(F,G,H,A,B,C,D,E, W[0].w+ K[50]);

	W[1].x += Wr1(W[0].z) + W[3].y + Wr2(W[1].y);
	RND(E,F,G,H,A,B,C,D, W[1].x+ K[51]);

	W[1].y += Wr1(W[0].w) + W[3].z + Wr2(W[1].z);
	RND(D,E,F,G,H,A,B,C, W[1].y+ K[52]);

	W[1].z += Wr1(W[1].x) + W[3].w + Wr2(W[1].w);
	RND(C,D,E,F,G,H,A,B, W[1].z+ K[53]);

	W[1].w += Wr1(W[1].y) + W[0].x + Wr2(W[2].x);
	RND(B,C,D,E,F,G,H,A, W[1].w+ K[54]);

	W[2].x += Wr1(W[1].z) + W[0].y + Wr2(W[2].y);
	RND(A,B,C,D,E,F,G,H, W[2].x+ K[55]);

	W[2].y += Wr1(W[1].w) + W[0].z + Wr2(W[2].z);
	RND(H,A,B,C,D,E,F,G, W[2].y+ K[56]);

	W[2].z += Wr1(W[2].x) + W[0].w + Wr2(W[2].w);
	RND(G,H,A,B,C,D,E,F, W[2].z+ K[57]);

	W[2].w += Wr1(W[2].y) + W[1].x + Wr2(W[3].x);
	RND(F,G,H,A,B,C,D,E, W[2].w+ K[58]);

	W[3].x += Wr1(W[2].z) + W[1].y + Wr2(W[3].y);
	RND(E,F,G,H,A,B,C,D, W[3].x+ K[59]);

	W[3].y += Wr1(W[2].w) + W[1].z + Wr2(W[3].z);
	RND(D,E,F,G,H,A,B,C, W[3].y+ K[60]);

	W[3].z += Wr1(W[3].x) + W[1].w + Wr2(W[3].w);
	RND(C,D,E,F,G,H,A,B, W[3].z+ K[61]);

	W[3].w += Wr1(W[3].y) + W[2].x + Wr2(W[0].x);
	RND(B,C,D,E,F,G,H,A, W[3].w+ K[62]);
	
#undef A
#undef B
#undef C
#undef D
#undef E
#undef F
#undef G
#undef H

	*state0 += (uint4)(K[73], K[77], K[78], K[79]);
	*state1 += (uint4)(K[66], K[67], K[80], K[81]);
}

__constant uint fixedW[64] =
{
	0x428a2f99,0xf1374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf794,
	0xf59b89c2,0x73924787,0x23c6886e,0xa42ca65c,0x15ed3627,0x4d6edcbf,0xe28217fc,0xef02488f,
	0xb707775c,0x0468c23f,0xe7e72b4c,0x49e1f1a2,0x4b99c816,0x926d1570,0xaa0fc072,0xadb36e2c,
	0xad87a3ea,0xbcb1d3a3,0x7b993186,0x562b9420,0xbff3ca0c,0xda4b0c23,0x6cd8711a,0x8f337caa,
	0xc91b1417,0xc359dce1,0xa83253a7,0x3b13c12d,0x9d3d725d,0xd9031a84,0xb1a03340,0x16f58012,
	0xe64fb6a2,0xe84d923a,0xe93a5730,0x09837686,0x078ff753,0x29833341,0xd5de0b7e,0x6948ccf4,
	0xe0a1adbe,0x7c728e11,0x511c78e4,0x315b45bd,0xfca71413,0xea28f96a,0x79703128,0x4e1ef848,
};

void SHA256_fixed(uint4*restrict state0,uint4*restrict state1)
{
	uint4 S0 = *state0;
	uint4 S1 = *state1;

#define A S0.x
#define B S0.y
#define C S0.z
#define D S0.w
#define E S1.x
#define F S1.y
#define G S1.z
#define H S1.w

	RND(A,B,C,D,E,F,G,H, fixedW[0]);
	RND(H,A,B,C,D,E,F,G, fixedW[1]);
	RND(G,H,A,B,C,D,E,F, fixedW[2]);
	RND(F,G,H,A,B,C,D,E, fixedW[3]);
	RND(E,F,G,H,A,B,C,D, fixedW[4]);
	RND(D,E,F,G,H,A,B,C, fixedW[5]);
	RND(C,D,E,F,G,H,A,B, fixedW[6]);
	RND(B,C,D,E,F,G,H,A, fixedW[7]);
	RND(A,B,C,D,E,F,G,H, fixedW[8]);
	RND(H,A,B,C,D,E,F,G, fixedW[9]);
	RND(G,H,A,B,C,D,E,F, fixedW[10]);
	RND(F,G,H,A,B,C,D,E, fixedW[11]);
	RND(E,F,G,H,A,B,C,D, fixedW[12]);
	RND(D,E,F,G,H,A,B,C, fixedW[13]);
	RND(C,D,E,F,G,H,A,B, fixedW[14]);
	RND(B,C,D,E,F,G,H,A, fixedW[15]);
	RND(A,B,C,D,E,F,G,H, fixedW[16]);
	RND(H,A,B,C,D,E,F,G, fixedW[17]);
	RND(G,H,A,B,C,D,E,F, fixedW[18]);
	RND(F,G,H,A,B,C,D,E, fixedW[19]);
	RND(E,F,G,H,A,B,C,D, fixedW[20]);
	RND(D,E,F,G,H,A,B,C, fixedW[21]);
	RND(C,D,E,F,G,H,A,B, fixedW[22]);
	RND(B,C,D,E,F,G,H,A, fixedW[23]);
	RND(A,B,C,D,E,F,G,H, fixedW[24]);
	RND(H,A,B,C,D,E,F,G, fixedW[25]);
	RND(G,H,A,B,C,D,E,F, fixedW[26]);
	RND(F,G,H,A,B,C,D,E, fixedW[27]);
	RND(E,F,G,H,A,B,C,D, fixedW[28]);
	RND(D,E,F,G,H,A,B,C, fixedW[29]);
	RND(C,D,E,F,G,H,A,B, fixedW[30]);
	RND(B,C,D,E,F,G,H,A, fixedW[31]);
	RND(A,B,C,D,E,F,G,H, fixedW[32]);
	RND(H,A,B,C,D,E,F,G, fixedW[33]);
	RND(G,H,A,B,C,D,E,F, fixedW[34]);
	RND(F,G,H,A,B,C,D,E, fixedW[35]);
	RND(E,F,G,H,A,B,C,D, fixedW[36]);
	RND(D,E,F,G,H,A,B,C, fixedW[37]);
	RND(C,D,E,F,G,H,A,B, fixedW[38]);
	RND(B,C,D,E,F,G,H,A, fixedW[39]);
	RND(A,B,C,D,E,F,G,H, fixedW[40]);
	RND(H,A,B,C,D,E,F,G, fixedW[41]);
	RND(G,H,A,B,C,D,E,F, fixedW[42]);
	RND(F,G,H,A,B,C,D,E, fixedW[43]);
	RND(E,F,G,H,A,B,C,D, fixedW[44]);
	RND(D,E,F,G,H,A,B,C, fixedW[45]);
	RND(C,D,E,F,G,H,A,B, fixedW[46]);
	RND(B,C,D,E,F,G,H,A, fixedW[47]);
	RND(A,B,C,D,E,F,G,H, fixedW[48]);
	RND(H,A,B,C,D,E,F,G, fixedW[49]);
	RND(G,H,A,B,C,D,E,F, fixedW[50]);
	RND(F,G,H,A,B,C,D,E, fixedW[51]);
	RND(E,F,G,H,A,B,C,D, fixedW[52]);
	RND(D,E,F,G,H,A,B,C, fixedW[53]);
	RND(C,D,E,F,G,H,A,B, fixedW[54]);
	RND(B,C,D,E,F,G,H,A, fixedW[55]);
	RND(A,B,C,D,E,F,G,H, fixedW[56]);
	RND(H,A,B,C,D,E,F,G, fixedW[57]);
	RND(G,H,A,B,C,D,E,F, fixedW[58]);
	RND(F,G,H,A,B,C,D,E, fixedW[59]);
	RND(E,F,G,H,A,B,C,D, fixedW[60]);
	RND(D,E,F,G,H,A,B,C, fixedW[61]);
	RND(C,D,E,F,G,H,A,B, fixedW[62]);
	RND(B,C,D,E,F,G,H,A, fixedW[63]);
	
#undef A
#undef B
#undef C
#undef D
#undef E
#undef F
#undef G
#undef H
	*state0 += S0;
	*state1 += S1;
}

void shittify(uint4 B[8])
{
	uint4 tmp[4];
	tmp[0] = (uint4)(B[1].x,B[2].y,B[3].z,B[0].w);
	tmp[1] = (uint4)(B[2].x,B[3].y,B[0].z,B[1].w);
	tmp[2] = (uint4)(B[3].x,B[0].y,B[1].z,B[2].w);
	tmp[3] = (uint4)(B[0].x,B[1].y,B[2].z,B[3].w);
	
#pragma unroll
	for(uint i=0; i<4; ++i)
		B[i] = EndianSwap(tmp[i]);

	tmp[0] = (uint4)(B[5].x,B[6].y,B[7].z,B[4].w);
	tmp[1] = (uint4)(B[6].x,B[7].y,B[4].z,B[5].w);
	tmp[2] = (uint4)(B[7].x,B[4].y,B[5].z,B[6].w);
	tmp[3] = (uint4)(B[4].x,B[5].y,B[6].z,B[7].w);
	
#pragma unroll
	for(uint i=0; i<4; ++i)
		B[i+4] = EndianSwap(tmp[i]);
}

void unshittify(uint4 B[8])
{
	uint4 tmp[4];
	tmp[0] = (uint4)(B[3].x,B[2].y,B[1].z,B[0].w);
	tmp[1] = (uint4)(B[0].x,B[3].y,B[2].z,B[1].w);
	tmp[2] = (uint4)(B[1].x,B[0].y,B[3].z,B[2].w);
	tmp[3] = (uint4)(B[2].x,B[1].y,B[0].z,B[3].w);
	
#pragma unroll
	for(uint i=0; i<4; ++i)
		B[i] = EndianSwap(tmp[i]);

	tmp[0] = (uint4)(B[7].x,B[6].y,B[5].z,B[4].w);
	tmp[1] = (uint4)(B[4].x,B[7].y,B[6].z,B[5].w);
	tmp[2] = (uint4)(B[5].x,B[4].y,B[7].z,B[6].w);
	tmp[3] = (uint4)(B[6].x,B[5].y,B[4].z,B[7].w);
	
#pragma unroll
	for(uint i=0; i<4; ++i)
		B[i+4] = EndianSwap(tmp[i]);
}

void salsa(uint4 B[8])
{
	uint4 w[4];

#pragma unroll
	for(uint i=0; i<4; ++i)
		w[i] = (B[i]^=B[i+4]);

#pragma unroll
	for(uint i=0; i<4; ++i)
	{
		w[0] ^= rotl(w[3]     +w[2]     , 7U);
		w[1] ^= rotl(w[0]     +w[3]     , 9U);
		w[2] ^= rotl(w[1]     +w[0]     ,13U);
		w[3] ^= rotl(w[2]     +w[1]     ,18U);
		w[2] ^= rotl(w[3].wxyz+w[0].zwxy, 7U);
		w[1] ^= rotl(w[2].wxyz+w[3].zwxy, 9U);
		w[0] ^= rotl(w[1].wxyz+w[2].zwxy,13U);
		w[3] ^= rotl(w[0].wxyz+w[1].zwxy,18U);
	}

#pragma unroll
	for(uint i=0; i<4; ++i)
		w[i] = (B[i+4]^=(B[i]+=w[i]));

#pragma unroll
	for(uint i=0; i<4; ++i)
	{
		w[0] ^= rotl(w[3]     +w[2]     , 7U);
		w[1] ^= rotl(w[0]     +w[3]     , 9U);
		w[2] ^= rotl(w[1]     +w[0]     ,13U);
		w[3] ^= rotl(w[2]     +w[1]     ,18U);
		w[2] ^= rotl(w[3].wxyz+w[0].zwxy, 7U);
		w[1] ^= rotl(w[2].wxyz+w[3].zwxy, 9U);
		w[0] ^= rotl(w[1].wxyz+w[2].zwxy,13U);
		w[3] ^= rotl(w[0].wxyz+w[1].zwxy,18U);
	}

#pragma unroll
	for(uint i=0; i<4; ++i)
		B[i+4] += w[i];
}

void scrypt_core(uint4 X[8], __global uint4*restrict lookup)
{
	shittify(X);
	const uint zSIZE = 8;
	const uint xSIZE = CONCURRENT_THREADS;
	uint x = get_global_id(0)%xSIZE;
	uint CO_tmp=xSIZE<<3U;
	uint CO_tmp2=x<<3U;

	for(uint y=0; y<1024/LOOKUP_GAP; ++y)
	{
		uint CO=y*CO_tmp+CO_tmp2;
#pragma unroll
		for(uint z=0; z<zSIZE; ++z,++CO)
			lookup[CO] = X[z];
		for(uint i=0; i<LOOKUP_GAP; ++i) 
			salsa(X);
	}
	
#if (LOOKUP_GAP != 1) && (LOOKUP_GAP != 2) && (LOOKUP_GAP != 4) && (LOOKUP_GAP != 8)
	{
		uint y = (1024/LOOKUP_GAP);
		uint CO=y*CO_tmp+CO_tmp2;
#pragma unroll
		for(uint z=0; z<zSIZE; ++z)
			lookup[CO] = X[z];
		for(uint i=0; i<1024%LOOKUP_GAP; ++i)
			salsa(X); 
	}
#endif
	for (uint i=0; i<1024; ++i) 
	{
		uint4 V[8];
		uint j = X[7].x & K[85];
		uint y = (j/LOOKUP_GAP);
		uint CO=y*CO_tmp+CO_tmp2;
#pragma unroll
		for(uint z=0; z<zSIZE; ++z)
			V[z] = lookup[CO+z];

#if (LOOKUP_GAP == 1)
#elif (LOOKUP_GAP == 2)
		if (j&1)
			salsa(V);
#else
		uint val = j%LOOKUP_GAP;
		for (uint z=0; z<val; ++z) 
			salsa(V);
#endif

#pragma unroll
		for(uint z=0; z<zSIZE; ++z)
			X[z] ^= V[z];
		salsa(X);
	}
	unshittify(X);
}

#define FOUND (0xFF)
#define SETFOUND(Xnonce) output[output[FOUND]++] = Xnonce

__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
__kernel void search(__global const uint4 * restrict input,
volatile __global uint*restrict output, __global uint4*restrict padcache,
const uint4 midstate0, const uint4 midstate16, const uint target)
{
	uint gid = get_global_id(0);
	uint4 X[8];
	uint4 tstate0, tstate1, ostate0, ostate1, tmp0, tmp1;
	uint4 data = (uint4)(input[4].x,input[4].y,input[4].z,gid);
	uint4 pad0 = midstate0, pad1 = midstate16;

	SHA256(&pad0,&pad1, data, (uint4)(K[84],0,0,0), (uint4)(0,0,0,0), (uint4)(0,0,0, K[86]));
	SHA256_fresh(&ostate0,&ostate1, pad0^ K[82], pad1^ K[82], K[82], K[82]);
	SHA256_fresh(&tstate0,&tstate1, pad0^ K[83], pad1^ K[83], K[83], K[83]);

	tmp0 = tstate0;
	tmp1 = tstate1;
	SHA256(&tstate0, &tstate1, input[0],input[1],input[2],input[3]);

#pragma unroll
	for (uint i=0; i<4; i++) 
	{
		pad0 = tstate0;
		pad1 = tstate1;
		X[i*2 ] = ostate0;
		X[i*2+1] = ostate1;

		SHA256(&pad0,&pad1, data, (uint4)(i+1,K[84],0,0), (uint4)(0,0,0,0), (uint4)(0,0,0, K[87]));
		SHA256(X+i*2,X+i*2+1, pad0, pad1, (uint4)(K[84], 0U, 0U, 0U), (uint4)(0U, 0U, 0U, K[88]));
	}
	scrypt_core(X,padcache);
	SHA256(&tmp0,&tmp1, X[0], X[1], X[2], X[3]);
	SHA256(&tmp0,&tmp1, X[4], X[5], X[6], X[7]);
	SHA256_fixed(&tmp0,&tmp1);
	SHA256(&ostate0,&ostate1, tmp0, tmp1, (uint4)(K[84], 0U, 0U, 0U), (uint4)(0U, 0U, 0U, K[88]));

	bool result = (EndianSwap(ostate1.w) <= target);
	if (result)
		SETFOUND(gid);
}

/*
 * AnimeCoin kernel implementation.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2014  phm
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author   phm <phm@inbox.com>
 */

#ifndef ANIMECOIN_CL
#define ANIMECOIN_CL

#if __ENDIAN_LITTLE__
#define SPH_LITTLE_ENDIAN 1
#else
#define SPH_BIG_ENDIAN 1
#endif

#define SPH_UPTR sph_u64

typedef unsigned int sph_u32;
typedef int sph_s32;
#ifndef __OPENCL_VERSION__
typedef unsigned long long sph_u64;
typedef long long sph_s64;
#else
typedef unsigned long sph_u64;
typedef long sph_s64;
#endif

#define SPH_64 1
#define SPH_64_TRUE 1

#define SPH_C32(x)    ((sph_u32)(x ## U))
#define SPH_T32(x)    ((x) & SPH_C32(0xFFFFFFFF))
#define SPH_ROTL32(x, n)   SPH_T32(((x) << (n)) | ((x) >> (32 - (n))))
#define SPH_ROTR32(x, n)   SPH_ROTL32(x, (32 - (n)))

#define SPH_C64(x)    ((sph_u64)(x ## UL))
#define SPH_T64(x)    ((x) & SPH_C64(0xFFFFFFFFFFFFFFFF))
#define SPH_ROTL64(x, n)   SPH_T64(((x) << (n)) | ((x) >> (64 - (n))))
#define SPH_ROTR64(x, n)   SPH_ROTL64(x, (64 - (n)))

#define SPH_ECHO_64 1
#define SPH_KECCAK_64 1
#define SPH_JH_64 1
#define SPH_SIMD_NOCOPY 0
#define SPH_KECCAK_NOCOPY 0
#define SPH_COMPACT_BLAKE_64 0
#define SPH_LUFFA_PARALLEL 0
#define SPH_SMALL_FOOTPRINT_GROESTL 0
#define SPH_GROESTL_BIG_ENDIAN 0

#define SPH_CUBEHASH_UNROLL 0
#define SPH_KECCAK_UNROLL   0

#include "blake.cl"
#include "bmw.cl"
#include "groestl.cl"
#include "jh.cl"
#include "keccak.cl"
#include "skein.cl"

#define SWAP4(x) as_uint(as_uchar4(x).wzyx)
#define SWAP8(x) as_ulong(as_uchar8(x).s76543210)

#if SPH_BIG_ENDIAN
    #define DEC64E(x) (x)
    #define DEC64BE(x) (*(const __global sph_u64 *) (x));
    #define DEC64LE(x) SWAP8(*(const __global sph_u64 *) (x));
#else
    #define DEC64E(x) SWAP8(x)
    #define DEC64BE(x) SWAP8(*(const __global sph_u64 *) (x));
    #define DEC64LE(x) (*(const __global sph_u64 *) (x));
#endif

__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
__kernel void search(__global unsigned char* block, volatile __global uint* output, const ulong target)
{
    uint gid = get_global_id(0);
    union {
        unsigned char h1[64];
        uint h4[16];
        ulong h8[8];
    } hash;

    // bmw
    sph_u64 BMW_H[16];
    for(unsigned u = 0; u < 16; u++)
        BMW_H[u] = BMW_IV512[u];

    sph_u64 BMW_h1[16], BMW_h2[16];
    sph_u64 mv[16];

    mv[0] = DEC64LE(block +   0);
    mv[1] = DEC64LE(block +   8);
    mv[2] = DEC64LE(block +  16);
    mv[3] = DEC64LE(block +  24);
    mv[4] = DEC64LE(block +  32);
    mv[5] = DEC64LE(block +  40);
    mv[6] = DEC64LE(block +  48);
    mv[7] = DEC64LE(block +  56);
    mv[8] = DEC64LE(block +  64);
    mv[9] = DEC64LE(block +  72);
    mv[9] &= 0x00000000FFFFFFFF;
    mv[9] ^= ((sph_u64) gid) << 32;
    mv[10] = 0x80;
    mv[11] = 0;
    mv[12] = 0;
    mv[13] = 0;
    mv[14] = 0;
    mv[15] = 0x280;
#define M(x)    (mv[x])
#define H(x)    (BMW_H[x])
#define dH(x)   (BMW_h2[x])

    FOLDb;

#undef M
#undef H
#undef dH

#define M(x)    (BMW_h2[x])
#define H(x)    (final_b[x])
#define dH(x)   (BMW_h1[x])

    FOLDb;

#undef M
#undef H
#undef dH

    hash.h8[0] = SWAP8(BMW_h1[8]);
    hash.h8[1] = SWAP8(BMW_h1[9]);
    hash.h8[2] = SWAP8(BMW_h1[10]);
    hash.h8[3] = SWAP8(BMW_h1[11]);
    hash.h8[4] = SWAP8(BMW_h1[12]);
    hash.h8[5] = SWAP8(BMW_h1[13]);
    hash.h8[6] = SWAP8(BMW_h1[14]);
    hash.h8[7] = SWAP8(BMW_h1[15]);

    // blake
{
    sph_u64 H0 = SPH_C64(0x6A09E667F3BCC908), H1 = SPH_C64(0xBB67AE8584CAA73B);
    sph_u64 H2 = SPH_C64(0x3C6EF372FE94F82B), H3 = SPH_C64(0xA54FF53A5F1D36F1);
    sph_u64 H4 = SPH_C64(0x510E527FADE682D1), H5 = SPH_C64(0x9B05688C2B3E6C1F);
    sph_u64 H6 = SPH_C64(0x1F83D9ABFB41BD6B), H7 = SPH_C64(0x5BE0CD19137E2179);
    sph_u64 S0 = 0, S1 = 0, S2 = 0, S3 = 0;
    sph_u64 T0 = SPH_C64(0xFFFFFFFFFFFFFC00) + (64 << 3), T1 = 0xFFFFFFFFFFFFFFFF;;

    if ((T0 = SPH_T64(T0 + 1024)) < 1024)
    {
        T1 = SPH_T64(T1 + 1);
    }
    sph_u64 M0, M1, M2, M3, M4, M5, M6, M7;
    sph_u64 M8, M9, MA, MB, MC, MD, ME, MF;
    sph_u64 V0, V1, V2, V3, V4, V5, V6, V7;
    sph_u64 V8, V9, VA, VB, VC, VD, VE, VF;
    M0 = hash.h8[0];
    M1 = hash.h8[1];
    M2 = hash.h8[2];
    M3 = hash.h8[3];
    M4 = hash.h8[4];
    M5 = hash.h8[5];
    M6 = hash.h8[6];
    M7 = hash.h8[7];
    M8 = 0x8000000000000000;
    M9 = 0;
    MA = 0;
    MB = 0;
    MC = 0;
    MD = 1;
    ME = 0;
    MF = 0x200;

    COMPRESS64;

    hash.h8[0] = H0;
    hash.h8[1] = H1;
    hash.h8[2] = H2;
    hash.h8[3] = H3;
    hash.h8[4] = H4;
    hash.h8[5] = H5;
    hash.h8[6] = H6;
    hash.h8[7] = H7;
}    
    bool dec = ((hash.h1[7] & 0x8) != 0);
    {

        // groestl
    
        sph_u64 H[16];
        for (unsigned int u = 0; u < 15; u ++)
            H[u] = 0;
    #if USE_LE
        H[15] = ((sph_u64)(512 & 0xFF) << 56) | ((sph_u64)(512 & 0xFF00) << 40);
    #else
        H[15] = (sph_u64)512;
    #endif
    
        sph_u64 g[16], m[16];
        m[0] = DEC64E(hash.h8[0]);
        m[1] = DEC64E(hash.h8[1]);
        m[2] = DEC64E(hash.h8[2]);
        m[3] = DEC64E(hash.h8[3]);
        m[4] = DEC64E(hash.h8[4]);
        m[5] = DEC64E(hash.h8[5]);
        m[6] = DEC64E(hash.h8[6]);
        m[7] = DEC64E(hash.h8[7]);
        for (unsigned int u = 0; u < 16; u ++)
            g[u] = m[u] ^ H[u];
        m[8] = 0x80; g[8] = m[8] ^ H[8];
        m[9] = 0; g[9] = m[9] ^ H[9];
        m[10] = 0; g[10] = m[10] ^ H[10];
        m[11] = 0; g[11] = m[11] ^ H[11];
        m[12] = 0; g[12] = m[12] ^ H[12];
        m[13] = 0; g[13] = m[13] ^ H[13];
        m[14] = 0; g[14] = m[14] ^ H[14];
        m[15] = 0x100000000000000; g[15] = m[15] ^ H[15];
        PERM_BIG_P(g);
        PERM_BIG_Q(m);
        for (unsigned int u = 0; u < 16; u ++)
            H[u] ^= g[u] ^ m[u];
        sph_u64 xH[16];
        for (unsigned int u = 0; u < 16; u ++)
            xH[u] = H[u];
        PERM_BIG_P(xH);
        for (unsigned int u = 0; u < 16; u ++)
            H[u] ^= xH[u];
        for (unsigned int u = 0; u < 8; u ++)
            hash.h8[u] = (dec ? DEC64E(H[u + 8]) : hash.h8[u]);

    }
    {

        // skein
    
        sph_u64 h0 = SPH_C64(0x4903ADFF749C51CE), h1 = SPH_C64(0x0D95DE399746DF03), h2 = SPH_C64(0x8FD1934127C79BCE), h3 = SPH_C64(0x9A255629FF352CB1), h4 = SPH_C64(0x5DB62599DF6CA7B0), h5 = SPH_C64(0xEABE394CA9D5C3F4), h6 = SPH_C64(0x991112C71A75B523), h7 = SPH_C64(0xAE18A40B660FCC33);
        sph_u64 m0, m1, m2, m3, m4, m5, m6, m7;
        sph_u64 bcount = 0;
    
        m0 = SWAP8(hash.h8[0]);
        m1 = SWAP8(hash.h8[1]);
        m2 = SWAP8(hash.h8[2]);
        m3 = SWAP8(hash.h8[3]);
        m4 = SWAP8(hash.h8[4]);
        m5 = SWAP8(hash.h8[5]);
        m6 = SWAP8(hash.h8[6]);
        m7 = SWAP8(hash.h8[7]);
        UBI_BIG(480, 64);
        bcount = 0;
        m0 = m1 = m2 = m3 = m4 = m5 = m6 = m7 = 0;
        UBI_BIG(510, 8);
        hash.h8[0] = (!dec ? SWAP8(h0) : hash.h8[0]);
        hash.h8[1] = (!dec ? SWAP8(h1) : hash.h8[1]);
        hash.h8[2] = (!dec ? SWAP8(h2) : hash.h8[2]);
        hash.h8[3] = (!dec ? SWAP8(h3) : hash.h8[3]);
        hash.h8[4] = (!dec ? SWAP8(h4) : hash.h8[4]);
        hash.h8[5] = (!dec ? SWAP8(h5) : hash.h8[5]);
        hash.h8[6] = (!dec ? SWAP8(h6) : hash.h8[6]);
        hash.h8[7] = (!dec ? SWAP8(h7) : hash.h8[7]);
    }
 
    // groestl

    sph_u64 H[16];
    for (unsigned int u = 0; u < 15; u ++)
        H[u] = 0;
#if USE_LE
    H[15] = ((sph_u64)(512 & 0xFF) << 56) | ((sph_u64)(512 & 0xFF00) << 40);
#else
    H[15] = (sph_u64)512;
#endif

    sph_u64 g[16], m[16];
    m[0] = DEC64E(hash.h8[0]);
    m[1] = DEC64E(hash.h8[1]);
    m[2] = DEC64E(hash.h8[2]);
    m[3] = DEC64E(hash.h8[3]);
    m[4] = DEC64E(hash.h8[4]);
    m[5] = DEC64E(hash.h8[5]);
    m[6] = DEC64E(hash.h8[6]);
    m[7] = DEC64E(hash.h8[7]);
    for (unsigned int u = 0; u < 16; u ++)
        g[u] = m[u] ^ H[u];
    m[8] = 0x80; g[8] = m[8] ^ H[8];
    m[9] = 0; g[9] = m[9] ^ H[9];
    m[10] = 0; g[10] = m[10] ^ H[10];
    m[11] = 0; g[11] = m[11] ^ H[11];
    m[12] = 0; g[12] = m[12] ^ H[12];
    m[13] = 0; g[13] = m[13] ^ H[13];
    m[14] = 0; g[14] = m[14] ^ H[14];
    m[15] = 0x100000000000000; g[15] = m[15] ^ H[15];
    PERM_BIG_P(g);
    PERM_BIG_Q(m);
    for (unsigned int u = 0; u < 16; u ++)
        H[u] ^= g[u] ^ m[u];
    sph_u64 xH[16];
    for (unsigned int u = 0; u < 16; u ++)
        xH[u] = H[u];
    PERM_BIG_P(xH);
    for (unsigned int u = 0; u < 16; u ++)
        H[u] ^= xH[u];
    for (unsigned int u = 0; u < 8; u ++)
        hash.h8[u] = DEC64E(H[u + 8]);

    // jh

    sph_u64 h0h = C64e(0x6fd14b963e00aa17), h0l = C64e(0x636a2e057a15d543), h1h = C64e(0x8a225e8d0c97ef0b), h1l = C64e(0xe9341259f2b3c361), h2h = C64e(0x891da0c1536f801e), h2l = C64e(0x2aa9056bea2b6d80), h3h = C64e(0x588eccdb2075baa6), h3l = C64e(0xa90f3a76baf83bf7);
    sph_u64 h4h = C64e(0x0169e60541e34a69), h4l = C64e(0x46b58a8e2e6fe65a), h5h = C64e(0x1047a7d0c1843c24), h5l = C64e(0x3b6e71b12d5ac199), h6h = C64e(0xcf57f6ec9db1f856), h6l = C64e(0xa706887c5716b156), h7h = C64e(0xe3c2fcdfe68517fb), h7l = C64e(0x545a4678cc8cdd4b);
    sph_u64 tmp;

    for(int i = 0; i < 2; i++)
    {
        if (i == 0) {
            h0h ^= DEC64E(hash.h8[0]);
            h0l ^= DEC64E(hash.h8[1]);
            h1h ^= DEC64E(hash.h8[2]);
            h1l ^= DEC64E(hash.h8[3]);
            h2h ^= DEC64E(hash.h8[4]);
            h2l ^= DEC64E(hash.h8[5]);
            h3h ^= DEC64E(hash.h8[6]);
            h3l ^= DEC64E(hash.h8[7]);
        } else if(i == 1) {
            h4h ^= DEC64E(hash.h8[0]);
            h4l ^= DEC64E(hash.h8[1]);
            h5h ^= DEC64E(hash.h8[2]);
            h5l ^= DEC64E(hash.h8[3]);
            h6h ^= DEC64E(hash.h8[4]);
            h6l ^= DEC64E(hash.h8[5]);
            h7h ^= DEC64E(hash.h8[6]);
            h7l ^= DEC64E(hash.h8[7]);
        
            h0h ^= 0x80;
            h3l ^= 0x2000000000000;
        }
        E8;
    }
    h4h ^= 0x80;
    h7l ^= 0x2000000000000;

    hash.h8[0] = DEC64E(h4h);
    hash.h8[1] = DEC64E(h4l);
    hash.h8[2] = DEC64E(h5h);
    hash.h8[3] = DEC64E(h5l);
    hash.h8[4] = DEC64E(h6h);
    hash.h8[5] = DEC64E(h6l);
    hash.h8[6] = DEC64E(h7h);
    hash.h8[7] = DEC64E(h7l);

    dec = ((hash.h1[7] & 0x8) != 0);
    {

        // blake
    
        sph_u64 H0 = SPH_C64(0x6A09E667F3BCC908), H1 = SPH_C64(0xBB67AE8584CAA73B);
        sph_u64 H2 = SPH_C64(0x3C6EF372FE94F82B), H3 = SPH_C64(0xA54FF53A5F1D36F1);
        sph_u64 H4 = SPH_C64(0x510E527FADE682D1), H5 = SPH_C64(0x9B05688C2B3E6C1F);
        sph_u64 H6 = SPH_C64(0x1F83D9ABFB41BD6B), H7 = SPH_C64(0x5BE0CD19137E2179);
        sph_u64 S0 = 0, S1 = 0, S2 = 0, S3 = 0;
        sph_u64 T0 = SPH_C64(0xFFFFFFFFFFFFFC00) + (64 << 3), T1 = 0xFFFFFFFFFFFFFFFF;;
    
        if ((T0 = SPH_T64(T0 + 1024)) < 1024)
        {
            T1 = SPH_T64(T1 + 1);
        }
        sph_u64 M0, M1, M2, M3, M4, M5, M6, M7;
        sph_u64 M8, M9, MA, MB, MC, MD, ME, MF;
        sph_u64 V0, V1, V2, V3, V4, V5, V6, V7;
        sph_u64 V8, V9, VA, VB, VC, VD, VE, VF;
        M0 = hash.h8[0];
        M1 = hash.h8[1];
        M2 = hash.h8[2];
        M3 = hash.h8[3];
        M4 = hash.h8[4];
        M5 = hash.h8[5];
        M6 = hash.h8[6];
        M7 = hash.h8[7];
        M8 = 0x8000000000000000;
        M9 = 0;
        MA = 0;
        MB = 0;
        MC = 0;
        MD = 1;
        ME = 0;
        MF = 0x200;
    
        COMPRESS64;
    
        hash.h8[0] = (dec ? H0 : hash.h8[0]);
        hash.h8[1] = (dec ? H1 : hash.h8[1]);
        hash.h8[2] = (dec ? H2 : hash.h8[2]);
        hash.h8[3] = (dec ? H3 : hash.h8[3]);
        hash.h8[4] = (dec ? H4 : hash.h8[4]);
        hash.h8[5] = (dec ? H5 : hash.h8[5]);
        hash.h8[6] = (dec ? H6 : hash.h8[6]);
        hash.h8[7] = (dec ? H7 : hash.h8[7]);

    }
    {
 
        // bmw
        sph_u64 BMW_H[16];
        for(unsigned u = 0; u < 16; u++)
            BMW_H[u] = BMW_IV512[u];
    
        sph_u64 BMW_h1[16], BMW_h2[16];
        sph_u64 mv[16];
    
        mv[ 0] = SWAP8(hash.h8[0]);
        mv[ 1] = SWAP8(hash.h8[1]);
        mv[ 2] = SWAP8(hash.h8[2]);
        mv[ 3] = SWAP8(hash.h8[3]);
        mv[ 4] = SWAP8(hash.h8[4]);
        mv[ 5] = SWAP8(hash.h8[5]);
        mv[ 6] = SWAP8(hash.h8[6]);
        mv[ 7] = SWAP8(hash.h8[7]);
        mv[ 8] = 0x80;
        mv[ 9] = 0;
        mv[10] = 0;
        mv[11] = 0;
        mv[12] = 0;
        mv[13] = 0;
        mv[14] = 0;
        mv[15] = 0x200;
    #define M(x)    (mv[x])
    #define H(x)    (BMW_H[x])
    #define dH(x)   (BMW_h2[x])
    
        FOLDb;
    
    #undef M
    #undef H
    #undef dH
    
    #define M(x)    (BMW_h2[x])
    #define H(x)    (final_b[x])
    #define dH(x)   (BMW_h1[x])
    
        FOLDb;
    
    #undef M
    #undef H
    #undef dH
    
        hash.h8[0] = (!dec ? SWAP8(BMW_h1[8]) : hash.h8[0]);
        hash.h8[1] = (!dec ? SWAP8(BMW_h1[9]) : hash.h8[1]);
        hash.h8[2] = (!dec ? SWAP8(BMW_h1[10]) : hash.h8[2]);
        hash.h8[3] = (!dec ? SWAP8(BMW_h1[11]) : hash.h8[3]);
        hash.h8[4] = (!dec ? SWAP8(BMW_h1[12]) : hash.h8[4]);
        hash.h8[5] = (!dec ? SWAP8(BMW_h1[13]) : hash.h8[5]);
        hash.h8[6] = (!dec ? SWAP8(BMW_h1[14]) : hash.h8[6]);
        hash.h8[7] = (!dec ? SWAP8(BMW_h1[15]) : hash.h8[7]);

    }

    // keccak

    sph_u64 a00 = 0, a01 = 0, a02 = 0, a03 = 0, a04 = 0;
    sph_u64 a10 = 0, a11 = 0, a12 = 0, a13 = 0, a14 = 0; 
    sph_u64 a20 = 0, a21 = 0, a22 = 0, a23 = 0, a24 = 0;
    sph_u64 a30 = 0, a31 = 0, a32 = 0, a33 = 0, a34 = 0;
    sph_u64 a40 = 0, a41 = 0, a42 = 0, a43 = 0, a44 = 0;

    a10 = SPH_C64(0xFFFFFFFFFFFFFFFF);
    a20 = SPH_C64(0xFFFFFFFFFFFFFFFF);
    a31 = SPH_C64(0xFFFFFFFFFFFFFFFF);
    a22 = SPH_C64(0xFFFFFFFFFFFFFFFF);
    a23 = SPH_C64(0xFFFFFFFFFFFFFFFF);
    a04 = SPH_C64(0xFFFFFFFFFFFFFFFF);

    a00 ^= SWAP8(hash.h8[0]);
    a10 ^= SWAP8(hash.h8[1]);
    a20 ^= SWAP8(hash.h8[2]);
    a30 ^= SWAP8(hash.h8[3]);
    a40 ^= SWAP8(hash.h8[4]);
    a01 ^= SWAP8(hash.h8[5]);
    a11 ^= SWAP8(hash.h8[6]);
    a21 ^= SWAP8(hash.h8[7]);
    a31 ^= 0x8000000000000001;
    KECCAK_F_1600;
    // Finalize the "lane complement"
    a10 = ~a10;
    a20 = ~a20;

    hash.h8[0] = SWAP8(a00);
    hash.h8[1] = SWAP8(a10);
    hash.h8[2] = SWAP8(a20);
    hash.h8[3] = SWAP8(a30);
    hash.h8[4] = SWAP8(a40);
    hash.h8[5] = SWAP8(a01);
    hash.h8[6] = SWAP8(a11);
    hash.h8[7] = SWAP8(a21);

    // skein

    sph_u64 h0 = SPH_C64(0x4903ADFF749C51CE), h1 = SPH_C64(0x0D95DE399746DF03), h2 = SPH_C64(0x8FD1934127C79BCE), h3 = SPH_C64(0x9A255629FF352CB1), h4 = SPH_C64(0x5DB62599DF6CA7B0), h5 = SPH_C64(0xEABE394CA9D5C3F4), h6 = SPH_C64(0x991112C71A75B523), h7 = SPH_C64(0xAE18A40B660FCC33);
    sph_u64 m0, m1, m2, m3, m4, m5, m6, m7;
    sph_u64 bcount = 0;

    m0 = SWAP8(hash.h8[0]);
    m1 = SWAP8(hash.h8[1]);
    m2 = SWAP8(hash.h8[2]);
    m3 = SWAP8(hash.h8[3]);
    m4 = SWAP8(hash.h8[4]);
    m5 = SWAP8(hash.h8[5]);
    m6 = SWAP8(hash.h8[6]);
    m7 = SWAP8(hash.h8[7]);
    UBI_BIG(480, 64);
    bcount = 0;
    m0 = m1 = m2 = m3 = m4 = m5 = m6 = m7 = 0;
    UBI_BIG(510, 8);
    hash.h8[0] = SWAP8(h0);
    hash.h8[1] = SWAP8(h1);
    hash.h8[2] = SWAP8(h2);
    hash.h8[3] = SWAP8(h3);
    hash.h8[4] = SWAP8(h4);
    hash.h8[5] = SWAP8(h5);
    hash.h8[6] = SWAP8(h6);
    hash.h8[7] = SWAP8(h7);

    dec = ((hash.h1[7] & 0x8) != 0);
    {

        // keccak
    
        sph_u64 a00 = 0, a01 = 0, a02 = 0, a03 = 0, a04 = 0;
        sph_u64 a10 = 0, a11 = 0, a12 = 0, a13 = 0, a14 = 0; 
        sph_u64 a20 = 0, a21 = 0, a22 = 0, a23 = 0, a24 = 0;
        sph_u64 a30 = 0, a31 = 0, a32 = 0, a33 = 0, a34 = 0;
        sph_u64 a40 = 0, a41 = 0, a42 = 0, a43 = 0, a44 = 0;
    
        a10 = SPH_C64(0xFFFFFFFFFFFFFFFF);
        a20 = SPH_C64(0xFFFFFFFFFFFFFFFF);
        a31 = SPH_C64(0xFFFFFFFFFFFFFFFF);
        a22 = SPH_C64(0xFFFFFFFFFFFFFFFF);
        a23 = SPH_C64(0xFFFFFFFFFFFFFFFF);
        a04 = SPH_C64(0xFFFFFFFFFFFFFFFF);
    
        a00 ^= SWAP8(hash.h8[0]);
        a10 ^= SWAP8(hash.h8[1]);
        a20 ^= SWAP8(hash.h8[2]);
        a30 ^= SWAP8(hash.h8[3]);
        a40 ^= SWAP8(hash.h8[4]);
        a01 ^= SWAP8(hash.h8[5]);
        a11 ^= SWAP8(hash.h8[6]);
        a21 ^= SWAP8(hash.h8[7]);
        a31 ^= 0x8000000000000001;
        KECCAK_F_1600;
        // Finalize the "lane complement"
        a10 = ~a10;
        a20 = ~a20;
    
        hash.h8[0] = (dec ? SWAP8(a00) : hash.h8[0]);
        hash.h8[1] = (dec ? SWAP8(a10) : hash.h8[1]);
        hash.h8[2] = (dec ? SWAP8(a20) : hash.h8[2]);
        hash.h8[3] = (dec ? SWAP8(a30) : hash.h8[3]);
        hash.h8[4] = (dec ? SWAP8(a40) : hash.h8[4]);
        hash.h8[5] = (dec ? SWAP8(a01) : hash.h8[5]);
        hash.h8[6] = (dec ? SWAP8(a11) : hash.h8[6]);
        hash.h8[7] = (dec ? SWAP8(a21) : hash.h8[7]);

    }
    {

        // jh
    
        sph_u64 h0h = C64e(0x6fd14b963e00aa17), h0l = C64e(0x636a2e057a15d543), h1h = C64e(0x8a225e8d0c97ef0b), h1l = C64e(0xe9341259f2b3c361), h2h = C64e(0x891da0c1536f801e), h2l = C64e(0x2aa9056bea2b6d80), h3h = C64e(0x588eccdb2075baa6), h3l = C64e(0xa90f3a76baf83bf7);
        sph_u64 h4h = C64e(0x0169e60541e34a69), h4l = C64e(0x46b58a8e2e6fe65a), h5h = C64e(0x1047a7d0c1843c24), h5l = C64e(0x3b6e71b12d5ac199), h6h = C64e(0xcf57f6ec9db1f856), h6l = C64e(0xa706887c5716b156), h7h = C64e(0xe3c2fcdfe68517fb), h7l = C64e(0x545a4678cc8cdd4b);
        sph_u64 tmp;
    
        for(int i = 0; i < 2; i++)
        {
            if (i == 0) {
                h0h ^= DEC64E(hash.h8[0]);
                h0l ^= DEC64E(hash.h8[1]);
                h1h ^= DEC64E(hash.h8[2]);
                h1l ^= DEC64E(hash.h8[3]);
                h2h ^= DEC64E(hash.h8[4]);
                h2l ^= DEC64E(hash.h8[5]);
                h3h ^= DEC64E(hash.h8[6]);
                h3l ^= DEC64E(hash.h8[7]);
            } else if(i == 1) {
                h4h ^= DEC64E(hash.h8[0]);
                h4l ^= DEC64E(hash.h8[1]);
                h5h ^= DEC64E(hash.h8[2]);
                h5l ^= DEC64E(hash.h8[3]);
                h6h ^= DEC64E(hash.h8[4]);
                h6l ^= DEC64E(hash.h8[5]);
                h7h ^= DEC64E(hash.h8[6]);
                h7l ^= DEC64E(hash.h8[7]);
            
                h0h ^= 0x80;
                h3l ^= 0x2000000000000;
            }
            E8;
        }
        h4h ^= 0x80;
        h7l ^= 0x2000000000000;
    
        hash.h8[0] = (!dec ? DEC64E(h4h) : hash.h8[0]);
        hash.h8[1] = (!dec ? DEC64E(h4l) : hash.h8[1]);
        hash.h8[2] = (!dec ? DEC64E(h5h) : hash.h8[2]);
        hash.h8[3] = (!dec ? DEC64E(h5l) : hash.h8[3]);
        hash.h8[4] = (!dec ? DEC64E(h6h) : hash.h8[4]);
        hash.h8[5] = (!dec ? DEC64E(h6l) : hash.h8[5]);
        hash.h8[6] = (!dec ? DEC64E(h7h) : hash.h8[6]);
        hash.h8[7] = (!dec ? DEC64E(h7l) : hash.h8[7]);
 
    }

    bool result = (SWAP8(hash.h8[3]) <= target);
    if (result)
        output[output[0xFF]++] = SWAP4(gid);
}

#endif // ANIMECOIN_CL

/*
 * X13 kernel implementation.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2014  phm
 * Copyright (c) 2014 Girino Vey
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author   phm <phm@inbox.com>
 */

#ifndef X13MOD_CL
#define X13MOD_CL

#if __ENDIAN_LITTLE__
#define SPH_LITTLE_ENDIAN 1
#else
#define SPH_BIG_ENDIAN 1
#endif

#define SPH_UPTR sph_u64

typedef unsigned int sph_u32;
typedef int sph_s32;
#ifndef __OPENCL_VERSION__
typedef unsigned long long sph_u64;
typedef long long sph_s64;
#else
typedef unsigned long sph_u64;
typedef long sph_s64;
#endif

#define SPH_64 1
#define SPH_64_TRUE 1

#define SPH_C32(x)    ((sph_u32)(x ## U))
#define SPH_T32(x)    ((x) & SPH_C32(0xFFFFFFFF))
#define SPH_ROTL32(x, n)   SPH_T32(((x) << (n)) | ((x) >> (32 - (n))))
#define SPH_ROTR32(x, n)   SPH_ROTL32(x, (32 - (n)))

#define SPH_C64(x)    ((sph_u64)(x ## UL))
#define SPH_T64(x)    ((x) & SPH_C64(0xFFFFFFFFFFFFFFFF))
#define SPH_ROTL64(x, n)   SPH_T64(((x) << (n)) | ((x) >> (64 - (n))))
#define SPH_ROTR64(x, n)   SPH_ROTL64(x, (64 - (n)))

#define SPH_ECHO_64 1
#define SPH_KECCAK_64 1
#define SPH_JH_64 1
#define SPH_SIMD_NOCOPY 0
#define SPH_KECCAK_NOCOPY 0
#define SPH_COMPACT_BLAKE_64 0
#define SPH_LUFFA_PARALLEL 0
#define SPH_SMALL_FOOTPRINT_GROESTL 0
#define SPH_GROESTL_BIG_ENDIAN 0
#define SPH_CUBEHASH_UNROLL 0
#define SPH_KECCAK_UNROLL   0
#define SPH_HAMSI_EXPAND_BIG 4

#include "blake.cl"
#include "bmw.cl"
#include "groestl.cl"
#include "jh.cl"
#include "keccak.cl"
#include "skein.cl"
#include "luffa.cl"
#include "cubehash.cl"
#include "shavite.cl"
#include "simd.cl"
#include "echo.cl"
#include "hamsi.cl"
#include "fugue.cl"

#define SWAP4(x) as_uint(as_uchar4(x).wzyx)
#define SWAP8(x) as_ulong(as_uchar8(x).s76543210)

#if SPH_BIG_ENDIAN
    #define DEC64E(x) (x)
    #define DEC64BE(x) (*(const __global sph_u64 *) (x));
#else
    #define DEC64E(x) SWAP8(x)
    #define DEC64BE(x) SWAP8(*(const __global sph_u64 *) (x));
#endif

typedef union {
    unsigned char h1[64];
    uint h4[16];
    ulong h8[8];
} hash_t;

__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
__kernel void blake(__global unsigned char* block, __global hash_t* hashes)
{
    uint gid = get_global_id(0);
    __global hash_t *hash = &(hashes[gid-get_global_offset(0)]);
    // blake

    sph_u64 H0 = SPH_C64(0x6A09E667F3BCC908), H1 = SPH_C64(0xBB67AE8584CAA73B);
    sph_u64 H2 = SPH_C64(0x3C6EF372FE94F82B), H3 = SPH_C64(0xA54FF53A5F1D36F1);
    sph_u64 H4 = SPH_C64(0x510E527FADE682D1), H5 = SPH_C64(0x9B05688C2B3E6C1F);
    sph_u64 H6 = SPH_C64(0x1F83D9ABFB41BD6B), H7 = SPH_C64(0x5BE0CD19137E2179);
    sph_u64 S0 = 0, S1 = 0, S2 = 0, S3 = 0;
    sph_u64 T0 = SPH_C64(0xFFFFFFFFFFFFFC00) + (80 << 3), T1 = 0xFFFFFFFFFFFFFFFF;;

    if ((T0 = SPH_T64(T0 + 1024)) < 1024)
    {
        T1 = SPH_T64(T1 + 1);
    }
    sph_u64 M0, M1, M2, M3, M4, M5, M6, M7;
    sph_u64 M8, M9, MA, MB, MC, MD, ME, MF;
    sph_u64 V0, V1, V2, V3, V4, V5, V6, V7;
    sph_u64 V8, V9, VA, VB, VC, VD, VE, VF;
    M0 = DEC64BE(block +   0);
    M1 = DEC64BE(block +   8);
    M2 = DEC64BE(block +  16);
    M3 = DEC64BE(block +  24);
    M4 = DEC64BE(block +  32);
    M5 = DEC64BE(block +  40);
    M6 = DEC64BE(block +  48);
    M7 = DEC64BE(block +  56);
    M8 = DEC64BE(block +  64);
    M9 = DEC64BE(block +  72);
    M9 &= 0xFFFFFFFF00000000;
    M9 ^= SWAP4(gid);
    MA = 0x8000000000000000;
    MB = 0;
    MC = 0;
    MD = 1;
    ME = 0;
    MF = 0x280;

    COMPRESS64;

    hash->h8[0] = H0;
    hash->h8[1] = H1;
    hash->h8[2] = H2;
    hash->h8[3] = H3;
    hash->h8[4] = H4;
    hash->h8[5] = H5;
    hash->h8[6] = H6;
    hash->h8[7] = H7;

    barrier(CLK_GLOBAL_MEM_FENCE);
}

__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
__kernel void bmw(__global hash_t* hashes)
{
    uint gid = get_global_id(0);
    __global hash_t *hash = &(hashes[gid-get_global_offset(0)]);
    // bmw
    sph_u64 BMW_H[16];
    for(unsigned u = 0; u < 16; u++)
        BMW_H[u] = BMW_IV512[u];

    sph_u64 BMW_h1[16], BMW_h2[16];
    sph_u64 mv[16];

    mv[ 0] = SWAP8(hash->h8[0]);
    mv[ 1] = SWAP8(hash->h8[1]);
    mv[ 2] = SWAP8(hash->h8[2]);
    mv[ 3] = SWAP8(hash->h8[3]);
    mv[ 4] = SWAP8(hash->h8[4]);
    mv[ 5] = SWAP8(hash->h8[5]);
    mv[ 6] = SWAP8(hash->h8[6]);
    mv[ 7] = SWAP8(hash->h8[7]);
    mv[ 8] = 0x80;
    mv[ 9] = 0;
    mv[10] = 0;
    mv[11] = 0;
    mv[12] = 0;
    mv[13] = 0;
    mv[14] = 0;
    mv[15] = 0x200;
#define M(x)    (mv[x])
#define H(x)    (BMW_H[x])
#define dH(x)   (BMW_h2[x])

    FOLDb;

#undef M
#undef H
#undef dH

#define M(x)    (BMW_h2[x])
#define H(x)    (final_b[x])
#define dH(x)   (BMW_h1[x])

    FOLDb;

#undef M
#undef H
#undef dH

    hash->h8[0] = SWAP8(BMW_h1[8]);
    hash->h8[1] = SWAP8(BMW_h1[9]);
    hash->h8[2] = SWAP8(BMW_h1[10]);
    hash->h8[3] = SWAP8(BMW_h1[11]);
    hash->h8[4] = SWAP8(BMW_h1[12]);
    hash->h8[5] = SWAP8(BMW_h1[13]);
    hash->h8[6] = SWAP8(BMW_h1[14]);
    hash->h8[7] = SWAP8(BMW_h1[15]);

    barrier(CLK_GLOBAL_MEM_FENCE);
}

__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
__kernel void groestl(__global hash_t* hashes)
{
    uint gid = get_global_id(0);
    __global hash_t *hash = &(hashes[gid-get_global_offset(0)]);

    __local sph_u64 T0_L[256], T1_L[256], T2_L[256], T3_L[256], T4_L[256], T5_L[256], T6_L[256], T7_L[256];

    int init = get_local_id(0);
    int step = get_local_size(0);

    for (int i = init; i < 256; i += step)
    {
        T0_L[i] = T0[i];
        T1_L[i] = T1[i];
        T2_L[i] = T2[i];
        T3_L[i] = T3[i];
        T4_L[i] = T4[i];
        T5_L[i] = T5[i];
        T6_L[i] = T6[i];
        T7_L[i] = T7[i];
    }
    barrier(CLK_LOCAL_MEM_FENCE);

#define T0 T0_L
#define T1 T1_L
#define T2 T2_L
#define T3 T3_L
#define T4 T4_L
#define T5 T5_L
#define T6 T6_L
#define T7 T7_L

    // groestl

    sph_u64 H[16];
    for (unsigned int u = 0; u < 15; u ++)
        H[u] = 0;
#if USE_LE
    H[15] = ((sph_u64)(512 & 0xFF) << 56) | ((sph_u64)(512 & 0xFF00) << 40);
#else
    H[15] = (sph_u64)512;
#endif

    sph_u64 g[16], m[16];
    m[0] = DEC64E(hash->h8[0]);
    m[1] = DEC64E(hash->h8[1]);
    m[2] = DEC64E(hash->h8[2]);
    m[3] = DEC64E(hash->h8[3]);
    m[4] = DEC64E(hash->h8[4]);
    m[5] = DEC64E(hash->h8[5]);
    m[6] = DEC64E(hash->h8[6]);
    m[7] = DEC64E(hash->h8[7]);
    for (unsigned int u = 0; u < 16; u ++)
        g[u] = m[u] ^ H[u];
    m[8] = 0x80; g[8] = m[8] ^ H[8];
    m[9] = 0; g[9] = m[9] ^ H[9];
    m[10] = 0; g[10] = m[10] ^ H[10];
    m[11] = 0; g[11] = m[11] ^ H[11];
    m[12] = 0; g[12] = m[12] ^ H[12];
    m[13] = 0; g[13] = m[13] ^ H[13];
    m[14] = 0; g[14] = m[14] ^ H[14];
    m[15] = 0x100000000000000; g[15] = m[15] ^ H[15];
    PERM_BIG_P(g);
    PERM_BIG_Q(m);
    for (unsigned int u = 0; u < 16; u ++)
        H[u] ^= g[u] ^ m[u];
    sph_u64 xH[16];
    for (unsigned int u = 0; u < 16; u ++)
        xH[u] = H[u];
    PERM_BIG_P(xH);
    for (unsigned int u = 0; u < 16; u ++)
        H[u] ^= xH[u];
    for (unsigned int u = 0; u < 8; u ++)
        hash->h8[u] = DEC64E(H[u + 8]);

    barrier(CLK_GLOBAL_MEM_FENCE);
}

__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
__kernel void skein(__global hash_t* hashes)
{
    uint gid = get_global_id(0);
    __global hash_t *hash = &(hashes[gid-get_global_offset(0)]);

    // skein

    sph_u64 h0 = SPH_C64(0x4903ADFF749C51CE), h1 = SPH_C64(0x0D95DE399746DF03), h2 = SPH_C64(0x8FD1934127C79BCE), h3 = SPH_C64(0x9A255629FF352CB1), h4 = SPH_C64(0x5DB62599DF6CA7B0), h5 = SPH_C64(0xEABE394CA9D5C3F4), h6 = SPH_C64(0x991112C71A75B523), h7 = SPH_C64(0xAE18A40B660FCC33);
    sph_u64 m0, m1, m2, m3, m4, m5, m6, m7;
    sph_u64 bcount = 0;

    m0 = SWAP8(hash->h8[0]);
    m1 = SWAP8(hash->h8[1]);
    m2 = SWAP8(hash->h8[2]);
    m3 = SWAP8(hash->h8[3]);
    m4 = SWAP8(hash->h8[4]);
    m5 = SWAP8(hash->h8[5]);
    m6 = SWAP8(hash->h8[6]);
    m7 = SWAP8(hash->h8[7]);
    UBI_BIG(480, 64);
    bcount = 0;
    m0 = m1 = m2 = m3 = m4 = m5 = m6 = m7 = 0;
    UBI_BIG(510, 8);
    hash->h8[0] = SWAP8(h0);
    hash->h8[1] = SWAP8(h1);
    hash->h8[2] = SWAP8(h2);
    hash->h8[3] = SWAP8(h3);
    hash->h8[4] = SWAP8(h4);
    hash->h8[5] = SWAP8(h5);
    hash->h8[6] = SWAP8(h6);
    hash->h8[7] = SWAP8(h7);
 
    barrier(CLK_GLOBAL_MEM_FENCE);
}

__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
__kernel void jh(__global hash_t* hashes)
{
    uint gid = get_global_id(0);
    __global hash_t *hash = &(hashes[gid-get_global_offset(0)]);

   // jh

    sph_u64 h0h = C64e(0x6fd14b963e00aa17), h0l = C64e(0x636a2e057a15d543), h1h = C64e(0x8a225e8d0c97ef0b), h1l = C64e(0xe9341259f2b3c361), h2h = C64e(0x891da0c1536f801e), h2l = C64e(0x2aa9056bea2b6d80), h3h = C64e(0x588eccdb2075baa6), h3l = C64e(0xa90f3a76baf83bf7);
    sph_u64 h4h = C64e(0x0169e60541e34a69), h4l = C64e(0x46b58a8e2e6fe65a), h5h = C64e(0x1047a7d0c1843c24), h5l = C64e(0x3b6e71b12d5ac199), h6h = C64e(0xcf57f6ec9db1f856), h6l = C64e(0xa706887c5716b156), h7h = C64e(0xe3c2fcdfe68517fb), h7l = C64e(0x545a4678cc8cdd4b);
    sph_u64 tmp;

    for(int i = 0; i < 2; i++)
    {
        if (i == 0) {
            h0h ^= DEC64E(hash->h8[0]);
            h0l ^= DEC64E(hash->h8[1]);
            h1h ^= DEC64E(hash->h8[2]);
            h1l ^= DEC64E(hash->h8[3]);
            h2h ^= DEC64E(hash->h8[4]);
            h2l ^= DEC64E(hash->h8[5]);
            h3h ^= DEC64E(hash->h8[6]);
            h3l ^= DEC64E(hash->h8[7]);
        } else if(i == 1) {
            h4h ^= DEC64E(hash->h8[0]);
            h4l ^= DEC64E(hash->h8[1]);
            h5h ^= DEC64E(hash->h8[2]);
            h5l ^= DEC64E(hash->h8[3]);
            h6h ^= DEC64E(hash->h8[4]);
            h6l ^= DEC64E(hash->h8[5]);
            h7h ^= DEC64E(hash->h8[6]);
            h7l ^= DEC64E(hash->h8[7]);
        
            h0h ^= 0x80;
            h3l ^= 0x2000000000000;
        }
        E8;
    }
    h4h ^= 0x80;
    h7l ^= 0x2000000000000;

    hash->h8[0] = DEC64E(h4h);
    hash->h8[1] = DEC64E(h4l);
    hash->h8[2] = DEC64E(h5h);
    hash->h8[3] = DEC64E(h5l);
    hash->h8[4] = DEC64E(h6h);
    hash->h8[5] = DEC64E(h6l);
    hash->h8[6] = DEC64E(h7h);
    hash->h8[7] = DEC64E(h7l);

    barrier(CLK_GLOBAL_MEM_FENCE);
}

__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
__kernel void keccak(__global hash_t* hashes)
{
    uint gid = get_global_id(0);
    __global hash_t *hash = &(hashes[gid-get_global_offset(0)]);

    // keccak

    sph_u64 a00 = 0, a01 = 0, a02 = 0, a03 = 0, a04 = 0;
    sph_u64 a10 = 0, a11 = 0, a12 = 0, a13 = 0, a14 = 0; 
    sph_u64 a20 = 0, a21 = 0, a22 = 0, a23 = 0, a24 = 0;
    sph_u64 a30 = 0, a31 = 0, a32 = 0, a33 = 0, a34 = 0;
    sph_u64 a40 = 0, a41 = 0, a42 = 0, a43 = 0, a44 = 0;

    a10 = SPH_C64(0xFFFFFFFFFFFFFFFF);
    a20 = SPH_C64(0xFFFFFFFFFFFFFFFF);
    a31 = SPH_C64(0xFFFFFFFFFFFFFFFF);
    a22 = SPH_C64(0xFFFFFFFFFFFFFFFF);
    a23 = SPH_C64(0xFFFFFFFFFFFFFFFF);
    a04 = SPH_C64(0xFFFFFFFFFFFFFFFF);

    a00 ^= SWAP8(hash->h8[0]);
    a10 ^= SWAP8(hash->h8[1]);
    a20 ^= SWAP8(hash->h8[2]);
    a30 ^= SWAP8(hash->h8[3]);
    a40 ^= SWAP8(hash->h8[4]);
    a01 ^= SWAP8(hash->h8[5]);
    a11 ^= SWAP8(hash->h8[6]);
    a21 ^= SWAP8(hash->h8[7]);
    a31 ^= 0x8000000000000001;
    KECCAK_F_1600;
    // Finalize the "lane complement"
    a10 = ~a10;
    a20 = ~a20;

    hash->h8[0] = SWAP8(a00);
    hash->h8[1] = SWAP8(a10);
    hash->h8[2] = SWAP8(a20);
    hash->h8[3] = SWAP8(a30);
    hash->h8[4] = SWAP8(a40);
    hash->h8[5] = SWAP8(a01);
    hash->h8[6] = SWAP8(a11);
    hash->h8[7] = SWAP8(a21);

    barrier(CLK_GLOBAL_MEM_FENCE);
}

__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
__kernel void luffa(__global hash_t* hashes)
{
    uint gid = get_global_id(0);
    __global hash_t *hash = &(hashes[gid-get_global_offset(0)]);

    // luffa

    sph_u32 V00 = SPH_C32(0x6d251e69), V01 = SPH_C32(0x44b051e0), V02 = SPH_C32(0x4eaa6fb4), V03 = SPH_C32(0xdbf78465), V04 = SPH_C32(0x6e292011), V05 = SPH_C32(0x90152df4), V06 = SPH_C32(0xee058139), V07 = SPH_C32(0xdef610bb);
    sph_u32 V10 = SPH_C32(0xc3b44b95), V11 = SPH_C32(0xd9d2f256), V12 = SPH_C32(0x70eee9a0), V13 = SPH_C32(0xde099fa3), V14 = SPH_C32(0x5d9b0557), V15 = SPH_C32(0x8fc944b3), V16 = SPH_C32(0xcf1ccf0e), V17 = SPH_C32(0x746cd581);
    sph_u32 V20 = SPH_C32(0xf7efc89d), V21 = SPH_C32(0x5dba5781), V22 = SPH_C32(0x04016ce5), V23 = SPH_C32(0xad659c05), V24 = SPH_C32(0x0306194f), V25 = SPH_C32(0x666d1836), V26 = SPH_C32(0x24aa230a), V27 = SPH_C32(0x8b264ae7);
    sph_u32 V30 = SPH_C32(0x858075d5), V31 = SPH_C32(0x36d79cce), V32 = SPH_C32(0xe571f7d7), V33 = SPH_C32(0x204b1f67), V34 = SPH_C32(0x35870c6a), V35 = SPH_C32(0x57e9e923), V36 = SPH_C32(0x14bcb808), V37 = SPH_C32(0x7cde72ce);
    sph_u32 V40 = SPH_C32(0x6c68e9be), V41 = SPH_C32(0x5ec41e22), V42 = SPH_C32(0xc825b7c7), V43 = SPH_C32(0xaffb4363), V44 = SPH_C32(0xf5df3999), V45 = SPH_C32(0x0fc688f1), V46 = SPH_C32(0xb07224cc), V47 = SPH_C32(0x03e86cea);

    DECL_TMP8(M);

    M0 = hash->h4[1];
    M1 = hash->h4[0];
    M2 = hash->h4[3];
    M3 = hash->h4[2];
    M4 = hash->h4[5];
    M5 = hash->h4[4];
    M6 = hash->h4[7];
    M7 = hash->h4[6];

    for(uint i = 0; i < 5; i++)
    {
        MI5;
        LUFFA_P5;

        if(i == 0) {
            M0 = hash->h4[9];
            M1 = hash->h4[8];
            M2 = hash->h4[11];
            M3 = hash->h4[10];
            M4 = hash->h4[13];
            M5 = hash->h4[12];
            M6 = hash->h4[15];
            M7 = hash->h4[14];
        } else if(i == 1) {
            M0 = 0x80000000;
            M1 = M2 = M3 = M4 = M5 = M6 = M7 = 0;
        } else if(i == 2) {
            M0 = M1 = M2 = M3 = M4 = M5 = M6 = M7 = 0;
        } else if(i == 3) {
            hash->h4[1] = V00 ^ V10 ^ V20 ^ V30 ^ V40;
            hash->h4[0] = V01 ^ V11 ^ V21 ^ V31 ^ V41;
            hash->h4[3] = V02 ^ V12 ^ V22 ^ V32 ^ V42;
            hash->h4[2] = V03 ^ V13 ^ V23 ^ V33 ^ V43;
            hash->h4[5] = V04 ^ V14 ^ V24 ^ V34 ^ V44;
            hash->h4[4] = V05 ^ V15 ^ V25 ^ V35 ^ V45;
            hash->h4[7] = V06 ^ V16 ^ V26 ^ V36 ^ V46;
            hash->h4[6] = V07 ^ V17 ^ V27 ^ V37 ^ V47;
        }
    }

    hash->h4[9] = V00 ^ V10 ^ V20 ^ V30 ^ V40;
    hash->h4[8] = V01 ^ V11 ^ V21 ^ V31 ^ V41;
    hash->h4[11] = V02 ^ V12 ^ V22 ^ V32 ^ V42;
    hash->h4[10] = V03 ^ V13 ^ V23 ^ V33 ^ V43;
    hash->h4[13] = V04 ^ V14 ^ V24 ^ V34 ^ V44;
    hash->h4[12] = V05 ^ V15 ^ V25 ^ V35 ^ V45;
    hash->h4[15] = V06 ^ V16 ^ V26 ^ V36 ^ V46;
    hash->h4[14] = V07 ^ V17 ^ V27 ^ V37 ^ V47;

    barrier(CLK_GLOBAL_MEM_FENCE);
}

__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
__kernel void cubehash(__global hash_t* hashes)
{
    uint gid = get_global_id(0);
    __global hash_t *hash = &(hashes[gid-get_global_offset(0)]);

    // cubehash.h1

    sph_u32 x0 = SPH_C32(0x2AEA2A61), x1 = SPH_C32(0x50F494D4), x2 = SPH_C32(0x2D538B8B), x3 = SPH_C32(0x4167D83E);
    sph_u32 x4 = SPH_C32(0x3FEE2313), x5 = SPH_C32(0xC701CF8C), x6 = SPH_C32(0xCC39968E), x7 = SPH_C32(0x50AC5695);
    sph_u32 x8 = SPH_C32(0x4D42C787), x9 = SPH_C32(0xA647A8B3), xa = SPH_C32(0x97CF0BEF), xb = SPH_C32(0x825B4537);
    sph_u32 xc = SPH_C32(0xEEF864D2), xd = SPH_C32(0xF22090C4), xe = SPH_C32(0xD0E5CD33), xf = SPH_C32(0xA23911AE);
    sph_u32 xg = SPH_C32(0xFCD398D9), xh = SPH_C32(0x148FE485), xi = SPH_C32(0x1B017BEF), xj = SPH_C32(0xB6444532);
    sph_u32 xk = SPH_C32(0x6A536159), xl = SPH_C32(0x2FF5781C), xm = SPH_C32(0x91FA7934), xn = SPH_C32(0x0DBADEA9);
    sph_u32 xo = SPH_C32(0xD65C8A2B), xp = SPH_C32(0xA5A70E75), xq = SPH_C32(0xB1C62456), xr = SPH_C32(0xBC796576);
    sph_u32 xs = SPH_C32(0x1921C8F7), xt = SPH_C32(0xE7989AF1), xu = SPH_C32(0x7795D246), xv = SPH_C32(0xD43E3B44);

    x0 ^= SWAP4(hash->h4[1]);
    x1 ^= SWAP4(hash->h4[0]);
    x2 ^= SWAP4(hash->h4[3]);
    x3 ^= SWAP4(hash->h4[2]);
    x4 ^= SWAP4(hash->h4[5]);
    x5 ^= SWAP4(hash->h4[4]);
    x6 ^= SWAP4(hash->h4[7]);
    x7 ^= SWAP4(hash->h4[6]);

    for (int i = 0; i < 13; i ++) {
        SIXTEEN_ROUNDS;

        if (i == 0) {
            x0 ^= SWAP4(hash->h4[9]);
            x1 ^= SWAP4(hash->h4[8]);
            x2 ^= SWAP4(hash->h4[11]);
            x3 ^= SWAP4(hash->h4[10]);
            x4 ^= SWAP4(hash->h4[13]);
            x5 ^= SWAP4(hash->h4[12]);
            x6 ^= SWAP4(hash->h4[15]);
            x7 ^= SWAP4(hash->h4[14]);
        } else if(i == 1) {
            x0 ^= 0x80;
        } else if (i == 2) {
            xv ^= SPH_C32(1);
        }
    }

    hash->h4[0] = x0;
    hash->h4[1] = x1;
    hash->h4[2] = x2;
    hash->h4[3] = x3;
    hash->h4[4] = x4;
    hash->h4[5] = x5;
    hash->h4[6] = x6;
    hash->h4[7] = x7;
    hash->h4[8] = x8;
    hash->h4[9] = x9;
    hash->h4[10] = xa;
    hash->h4[11] = xb;
    hash->h4[12] = xc;
    hash->h4[13] = xd;
    hash->h4[14] = xe;
    hash->h4[15] = xf;

    barrier(CLK_GLOBAL_MEM_FENCE);
}

__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
__kernel void shavite(__global hash_t* hashes)
{
    uint gid = get_global_id(0);
    __global hash_t *hash = &(hashes[gid-get_global_offset(0)]);
    __local sph_u32 AES0[256], AES1[256], AES2[256], AES3[256];

    int init = get_local_id(0);
    int step = get_local_size(0);

    for (int i = init; i < 256; i += step)
    {
        AES0[i] = AES0_C[i];
        AES1[i] = AES1_C[i];
        AES2[i] = AES2_C[i];
        AES3[i] = AES3_C[i];
    }

    barrier(CLK_LOCAL_MEM_FENCE);

    // shavite
    // IV
    sph_u32 h0 = SPH_C32(0x72FCCDD8), h1 = SPH_C32(0x79CA4727), h2 = SPH_C32(0x128A077B), h3 = SPH_C32(0x40D55AEC);
    sph_u32 h4 = SPH_C32(0xD1901A06), h5 = SPH_C32(0x430AE307), h6 = SPH_C32(0xB29F5CD1), h7 = SPH_C32(0xDF07FBFC);
    sph_u32 h8 = SPH_C32(0x8E45D73D), h9 = SPH_C32(0x681AB538), hA = SPH_C32(0xBDE86578), hB = SPH_C32(0xDD577E47);
    sph_u32 hC = SPH_C32(0xE275EADE), hD = SPH_C32(0x502D9FCD), hE = SPH_C32(0xB9357178), hF = SPH_C32(0x022A4B9A);

    // state
    sph_u32 rk00, rk01, rk02, rk03, rk04, rk05, rk06, rk07;
    sph_u32 rk08, rk09, rk0A, rk0B, rk0C, rk0D, rk0E, rk0F;
    sph_u32 rk10, rk11, rk12, rk13, rk14, rk15, rk16, rk17;
    sph_u32 rk18, rk19, rk1A, rk1B, rk1C, rk1D, rk1E, rk1F;

    sph_u32 sc_count0 = (64 << 3), sc_count1 = 0, sc_count2 = 0, sc_count3 = 0;

    rk00 = hash->h4[0];
    rk01 = hash->h4[1];
    rk02 = hash->h4[2];
    rk03 = hash->h4[3];
    rk04 = hash->h4[4];
    rk05 = hash->h4[5];
    rk06 = hash->h4[6];
    rk07 = hash->h4[7];
    rk08 = hash->h4[8];
    rk09 = hash->h4[9];
    rk0A = hash->h4[10];
    rk0B = hash->h4[11];
    rk0C = hash->h4[12];
    rk0D = hash->h4[13];
    rk0E = hash->h4[14];
    rk0F = hash->h4[15];
    rk10 = 0x80;
    rk11 = rk12 = rk13 = rk14 = rk15 = rk16 = rk17 = rk18 = rk19 = rk1A = 0;
    rk1B = 0x2000000;
    rk1C = rk1D = rk1E = 0;
    rk1F = 0x2000000;

    c512(buf);

    hash->h4[0] = h0;
    hash->h4[1] = h1;
    hash->h4[2] = h2;
    hash->h4[3] = h3;
    hash->h4[4] = h4;
    hash->h4[5] = h5;
    hash->h4[6] = h6;
    hash->h4[7] = h7;
    hash->h4[8] = h8;
    hash->h4[9] = h9;
    hash->h4[10] = hA;
    hash->h4[11] = hB;
    hash->h4[12] = hC;
    hash->h4[13] = hD;
    hash->h4[14] = hE;
    hash->h4[15] = hF;

    barrier(CLK_GLOBAL_MEM_FENCE);
}

__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
__kernel void simd(__global hash_t* hashes)
{
    uint gid = get_global_id(0);
    __global hash_t *hash = &(hashes[gid-get_global_offset(0)]);

    // simd
    s32 q[256];
    unsigned char x[128];
    for(unsigned int i = 0; i < 64; i++)
	x[i] = hash->h1[i];
    for(unsigned int i = 64; i < 128; i++)
	x[i] = 0;

    u32 A0 = C32(0x0BA16B95), A1 = C32(0x72F999AD), A2 = C32(0x9FECC2AE), A3 = C32(0xBA3264FC), A4 = C32(0x5E894929), A5 = C32(0x8E9F30E5), A6 = C32(0x2F1DAA37), A7 = C32(0xF0F2C558);
    u32 B0 = C32(0xAC506643), B1 = C32(0xA90635A5), B2 = C32(0xE25B878B), B3 = C32(0xAAB7878F), B4 = C32(0x88817F7A), B5 = C32(0x0A02892B), B6 = C32(0x559A7550), B7 = C32(0x598F657E);
    u32 C0 = C32(0x7EEF60A1), C1 = C32(0x6B70E3E8), C2 = C32(0x9C1714D1), C3 = C32(0xB958E2A8), C4 = C32(0xAB02675E), C5 = C32(0xED1C014F), C6 = C32(0xCD8D65BB), C7 = C32(0xFDB7A257);
    u32 D0 = C32(0x09254899), D1 = C32(0xD699C7BC), D2 = C32(0x9019B6DC), D3 = C32(0x2B9022E4), D4 = C32(0x8FA14956), D5 = C32(0x21BF9BD3), D6 = C32(0xB94D0943), D7 = C32(0x6FFDDC22);

    FFT256(0, 1, 0, ll1);
    for (int i = 0; i < 256; i ++) {
        s32 tq;

        tq = q[i] + yoff_b_n[i];
        tq = REDS2(tq);
        tq = REDS1(tq);
        tq = REDS1(tq);
        q[i] = (tq <= 128 ? tq : tq - 257);
    }

    A0 ^= hash->h4[0];
    A1 ^= hash->h4[1];
    A2 ^= hash->h4[2];
    A3 ^= hash->h4[3];
    A4 ^= hash->h4[4];
    A5 ^= hash->h4[5];
    A6 ^= hash->h4[6];
    A7 ^= hash->h4[7];
    B0 ^= hash->h4[8];
    B1 ^= hash->h4[9];
    B2 ^= hash->h4[10];
    B3 ^= hash->h4[11];
    B4 ^= hash->h4[12];
    B5 ^= hash->h4[13];
    B6 ^= hash->h4[14];
    B7 ^= hash->h4[15];

    ONE_ROUND_BIG(0_, 0,  3, 23, 17, 27);
    ONE_ROUND_BIG(1_, 1, 28, 19, 22,  7);
    ONE_ROUND_BIG(2_, 2, 29,  9, 15,  5);
    ONE_ROUND_BIG(3_, 3,  4, 13, 10, 25);

    STEP_BIG(
        C32(0x0BA16B95), C32(0x72F999AD), C32(0x9FECC2AE), C32(0xBA3264FC),
        C32(0x5E894929), C32(0x8E9F30E5), C32(0x2F1DAA37), C32(0xF0F2C558),
        IF,  4, 13, PP8_4_);
    STEP_BIG(
        C32(0xAC506643), C32(0xA90635A5), C32(0xE25B878B), C32(0xAAB7878F),
        C32(0x88817F7A), C32(0x0A02892B), C32(0x559A7550), C32(0x598F657E),
        IF, 13, 10, PP8_5_);
    STEP_BIG(
        C32(0x7EEF60A1), C32(0x6B70E3E8), C32(0x9C1714D1), C32(0xB958E2A8),
        C32(0xAB02675E), C32(0xED1C014F), C32(0xCD8D65BB), C32(0xFDB7A257),
        IF, 10, 25, PP8_6_);
    STEP_BIG(
        C32(0x09254899), C32(0xD699C7BC), C32(0x9019B6DC), C32(0x2B9022E4),
        C32(0x8FA14956), C32(0x21BF9BD3), C32(0xB94D0943), C32(0x6FFDDC22),
        IF, 25,  4, PP8_0_);

    u32 COPY_A0 = A0, COPY_A1 = A1, COPY_A2 = A2, COPY_A3 = A3, COPY_A4 = A4, COPY_A5 = A5, COPY_A6 = A6, COPY_A7 = A7;
    u32 COPY_B0 = B0, COPY_B1 = B1, COPY_B2 = B2, COPY_B3 = B3, COPY_B4 = B4, COPY_B5 = B5, COPY_B6 = B6, COPY_B7 = B7;
    u32 COPY_C0 = C0, COPY_C1 = C1, COPY_C2 = C2, COPY_C3 = C3, COPY_C4 = C4, COPY_C5 = C5, COPY_C6 = C6, COPY_C7 = C7;
    u32 COPY_D0 = D0, COPY_D1 = D1, COPY_D2 = D2, COPY_D3 = D3, COPY_D4 = D4, COPY_D5 = D5, COPY_D6 = D6, COPY_D7 = D7;

    #define q SIMD_Q

    A0 ^= 0x200;

    ONE_ROUND_BIG(0_, 0,  3, 23, 17, 27);
    ONE_ROUND_BIG(1_, 1, 28, 19, 22,  7);
    ONE_ROUND_BIG(2_, 2, 29,  9, 15,  5);
    ONE_ROUND_BIG(3_, 3,  4, 13, 10, 25);
    STEP_BIG(
        COPY_A0, COPY_A1, COPY_A2, COPY_A3,
        COPY_A4, COPY_A5, COPY_A6, COPY_A7,
        IF,  4, 13, PP8_4_);
    STEP_BIG(
        COPY_B0, COPY_B1, COPY_B2, COPY_B3,
        COPY_B4, COPY_B5, COPY_B6, COPY_B7,
        IF, 13, 10, PP8_5_);
    STEP_BIG(
        COPY_C0, COPY_C1, COPY_C2, COPY_C3,
        COPY_C4, COPY_C5, COPY_C6, COPY_C7,
        IF, 10, 25, PP8_6_);
    STEP_BIG(
        COPY_D0, COPY_D1, COPY_D2, COPY_D3,
        COPY_D4, COPY_D5, COPY_D6, COPY_D7,
        IF, 25,  4, PP8_0_);
    #undef q

    hash->h4[0] = A0;
    hash->h4[1] = A1;
    hash->h4[2] = A2;
    hash->h4[3] = A3;
    hash->h4[4] = A4;
    hash->h4[5] = A5;
    hash->h4[6] = A6;
    hash->h4[7] = A7;
    hash->h4[8] = B0;
    hash->h4[9] = B1;
    hash->h4[10] = B2;
    hash->h4[11] = B3;
    hash->h4[12] = B4;
    hash->h4[13] = B5;
    hash->h4[14] = B6;
    hash->h4[15] = B7;

    barrier(CLK_GLOBAL_MEM_FENCE);
}

#ifndef X13MODOLD

__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
__kernel void echo(__global hash_t* hashes)
{
    uint gid = get_global_id(0);
    uint offset = get_global_offset(0);
    hash_t hash;
    __global hash_t *hashp = &(hashes[gid-offset]);

    __local sph_u32 AES0[256], AES1[256], AES2[256], AES3[256];

    int init = get_local_id(0);
    int step = get_local_size(0);

    for (int i = init; i < 256; i += step)
    {
        AES0[i] = AES0_C[i];
        AES1[i] = AES1_C[i];
        AES2[i] = AES2_C[i];
        AES3[i] = AES3_C[i];
    }

    barrier(CLK_LOCAL_MEM_FENCE);

    for (int i = 0; i < 8; i++) {
        hash.h8[i] = hashes[gid-offset].h8[i];
    }

    // echo
    sph_u64 W00, W01, W10, W11, W20, W21, W30, W31, W40, W41, W50, W51, W60, W61, W70, W71, W80, W81, W90, W91, WA0, WA1, WB0, WB1, WC0, WC1, WD0, WD1, WE0, WE1, WF0, WF1;
    sph_u64 Vb00, Vb01, Vb10, Vb11, Vb20, Vb21, Vb30, Vb31, Vb40, Vb41, Vb50, Vb51, Vb60, Vb61, Vb70, Vb71;
    Vb00 = Vb10 = Vb20 = Vb30 = Vb40 = Vb50 = Vb60 = Vb70 = 512UL;
    Vb01 = Vb11 = Vb21 = Vb31 = Vb41 = Vb51 = Vb61 = Vb71 = 0;

    sph_u32 K0 = 512;
    sph_u32 K1 = 0;
    sph_u32 K2 = 0;
    sph_u32 K3 = 0;

    W00 = Vb00;
    W01 = Vb01;
    W10 = Vb10;
    W11 = Vb11;
    W20 = Vb20;
    W21 = Vb21;
    W30 = Vb30;
    W31 = Vb31;
    W40 = Vb40;
    W41 = Vb41;
    W50 = Vb50;
    W51 = Vb51;
    W60 = Vb60;
    W61 = Vb61;
    W70 = Vb70;
    W71 = Vb71;
    W80 = hash.h8[0];
    W81 = hash.h8[1];
    W90 = hash.h8[2];
    W91 = hash.h8[3];
    WA0 = hash.h8[4];
    WA1 = hash.h8[5];
    WB0 = hash.h8[6];
    WB1 = hash.h8[7];
    WC0 = 0x80;
    WC1 = 0;
    WD0 = 0;
    WD1 = 0;
    WE0 = 0;
    WE1 = 0x200000000000000;
    WF0 = 0x200;
    WF1 = 0;

    for (unsigned u = 0; u < 10; u ++) {
        BIG_ROUND;
    }

    hashp->h8[0] = hash.h8[0] ^ Vb00 ^ W00 ^ W80;
    hashp->h8[1] = hash.h8[1] ^ Vb01 ^ W01 ^ W81;
    hashp->h8[2] = hash.h8[2] ^ Vb10 ^ W10 ^ W90;
    hashp->h8[3] = hash.h8[3] ^ Vb11 ^ W11 ^ W91;
    hashp->h8[4] = hash.h8[4] ^ Vb20 ^ W20 ^ WA0;
    hashp->h8[5] = hash.h8[5] ^ Vb21 ^ W21 ^ WA1;
    hashp->h8[6] = hash.h8[6] ^ Vb30 ^ W30 ^ WB0;
    hashp->h8[7] = hash.h8[7] ^ Vb31 ^ W31 ^ WB1;

    barrier(CLK_GLOBAL_MEM_FENCE);
}

__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
__kernel void hamsi(__global hash_t* hashes)
{
    uint gid = get_global_id(0);
    uint offset = get_global_offset(0);
    hash_t hash;
    __global hash_t *hashp = &(hashes[gid-offset]);

    sph_u32 c0 = HAMSI_IV512[0], c1 = HAMSI_IV512[1], c2 = HAMSI_IV512[2], c3 = HAMSI_IV512[3];
    sph_u32 c4 = HAMSI_IV512[4], c5 = HAMSI_IV512[5], c6 = HAMSI_IV512[6], c7 = HAMSI_IV512[7];
    sph_u32 c8 = HAMSI_IV512[8], c9 = HAMSI_IV512[9], cA = HAMSI_IV512[10], cB = HAMSI_IV512[11];
    sph_u32 cC = HAMSI_IV512[12], cD = HAMSI_IV512[13], cE = HAMSI_IV512[14], cF = HAMSI_IV512[15];
    sph_u32 m0, m1, m2, m3, m4, m5, m6, m7;
    sph_u32 m8, m9, mA, mB, mC, mD, mE, mF;
    sph_u32 h[16] = { c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, cA, cB, cC, cD, cE, cF };

    for (int i = 0; i < 8; i++) {
        hash.h8[i] = hashes[gid-offset].h8[i];
    }

#define buf(u) hash.h1[i + u]
    for(int i = 0; i < 64; i += 8) {
        INPUT_BIG;
        P_BIG;
        T_BIG;
    }
#undef buf
#define buf(u) (u == 0 ? 0x80 : 0)
    INPUT_BIG;
    P_BIG;
    T_BIG;
#undef buf
#define buf(u) (u == 6 ? 2 : 0)
    INPUT_BIG;
    PF_BIG;
    T_BIG;

    for (unsigned u = 0; u < 16; u ++)
        hashp->h4[u] = h[u];

    barrier(CLK_GLOBAL_MEM_FENCE);
}

__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
__kernel void fugue(__global hash_t* hashes, __global uint* output, const ulong target)
{
    uint gid = get_global_id(0);
    uint offset = get_global_offset(0);
    hash_t hash;
    __global hash_t *hashp = &(hashes[gid-offset]);

    for (int i = 0; i < 8; i++) {
        hash.h8[i] = hashes[gid-offset].h8[i];
    }

    // fugue
    sph_u32 S00, S01, S02, S03, S04, S05, S06, S07, S08, S09;
    sph_u32 S10, S11, S12, S13, S14, S15, S16, S17, S18, S19;
    sph_u32 S20, S21, S22, S23, S24, S25, S26, S27, S28, S29;
    sph_u32 S30, S31, S32, S33, S34, S35;

    ulong fc_bit_count = (sph_u64) 64 << 3;

    S00 = S01 = S02 = S03 = S04 = S05 = S06 = S07 = S08 = S09 = S10 = S11 = S12 = S13 = S14 = S15 = S16 = S17 = S18 = S19 = 0;
    S20 = SPH_C32(0x8807a57e); S21 = SPH_C32(0xe616af75); S22 = SPH_C32(0xc5d3e4db); S23 = SPH_C32(0xac9ab027);
    S24 = SPH_C32(0xd915f117); S25 = SPH_C32(0xb6eecc54); S26 = SPH_C32(0x06e8020b); S27 = SPH_C32(0x4a92efd1);
    S28 = SPH_C32(0xaac6e2c9); S29 = SPH_C32(0xddb21398); S30 = SPH_C32(0xcae65838); S31 = SPH_C32(0x437f203f);
    S32 = SPH_C32(0x25ea78e7); S33 = SPH_C32(0x951fddd6); S34 = SPH_C32(0xda6ed11d); S35 = SPH_C32(0xe13e3567);

    FUGUE512_3((hash.h4[0x0]), (hash.h4[0x1]), (hash.h4[0x2]));
    FUGUE512_3((hash.h4[0x3]), (hash.h4[0x4]), (hash.h4[0x5]));
    FUGUE512_3((hash.h4[0x6]), (hash.h4[0x7]), (hash.h4[0x8]));
    FUGUE512_3((hash.h4[0x9]), (hash.h4[0xA]), (hash.h4[0xB]));
    FUGUE512_3((hash.h4[0xC]), (hash.h4[0xD]), (hash.h4[0xE]));
    FUGUE512_3((hash.h4[0xF]), as_uint2(fc_bit_count).y, as_uint2(fc_bit_count).x);

    // apply round shift if necessary
    int i;

    for (i = 0; i < 32; i ++) {
        ROR3;
        CMIX36(S00, S01, S02, S04, S05, S06, S18, S19, S20);
        SMIX(S00, S01, S02, S03);
    }
    for (i = 0; i < 13; i ++) {
        S04 ^= S00;
        S09 ^= S00;
        S18 ^= S00;
        S27 ^= S00;
        ROR9;
        SMIX(S00, S01, S02, S03);
        S04 ^= S00;
        S10 ^= S00;
        S18 ^= S00;
        S27 ^= S00;
        ROR9;
        SMIX(S00, S01, S02, S03);
        S04 ^= S00;
        S10 ^= S00;
        S19 ^= S00;
        S27 ^= S00;
        ROR9;
        SMIX(S00, S01, S02, S03);
        S04 ^= S00;
        S10 ^= S00;
        S19 ^= S00;
        S28 ^= S00;
        ROR8;
        SMIX(S00, S01, S02, S03);
    }
    S04 ^= S00;
    S09 ^= S00;
    S18 ^= S00;
    S27 ^= S00;

    hash.h4[0] = SWAP4(S01);
    hash.h4[1] = SWAP4(S02);
    hash.h4[2] = SWAP4(S03);
    hash.h4[3] = SWAP4(S04);
    hash.h4[4] = SWAP4(S09);
    hash.h4[5] = SWAP4(S10);
    hash.h4[6] = SWAP4(S11);
    hash.h4[7] = SWAP4(S12);
    hash.h4[8] = SWAP4(S18);
    hash.h4[9] = SWAP4(S19);
    hash.h4[10] = SWAP4(S20);
    hash.h4[11] = SWAP4(S21);
    hash.h4[12] = SWAP4(S27);
    hash.h4[13] = SWAP4(S28);
    hash.h4[14] = SWAP4(S29);
    hash.h4[15] = SWAP4(S30);

    bool result = (hash.h8[3] <= target);
    if (result)
	output[atomic_inc(output+0xFF)] = SWAP4(gid);

    barrier(CLK_GLOBAL_MEM_FENCE);
}

#else

__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
__kernel void echo_hamsi_fugue(__global hash_t* hashes, __global uint* output, const ulong target)
{
    uint gid = get_global_id(0);
    uint offset = get_global_offset(0);
    hash_t hash;

    __local sph_u32 AES0[256], AES1[256], AES2[256], AES3[256];

    int init = get_local_id(0);
    int step = get_local_size(0);

    for (int i = init; i < 256; i += step)
    {
        AES0[i] = AES0_C[i];
        AES1[i] = AES1_C[i];
        AES2[i] = AES2_C[i];
        AES3[i] = AES3_C[i];
    }

    barrier(CLK_LOCAL_MEM_FENCE);

    for (int i = 0; i < 8; i++) {
        hash.h8[i] = hashes[gid-offset].h8[i];
    }

    // echo

    {

    sph_u64 W00, W01, W10, W11, W20, W21, W30, W31, W40, W41, W50, W51, W60, W61, W70, W71, W80, W81, W90, W91, WA0, WA1, WB0, WB1, WC0, WC1, WD0, WD1, WE0, WE1, WF0, WF1;
    sph_u64 Vb00, Vb01, Vb10, Vb11, Vb20, Vb21, Vb30, Vb31, Vb40, Vb41, Vb50, Vb51, Vb60, Vb61, Vb70, Vb71;
    Vb00 = Vb10 = Vb20 = Vb30 = Vb40 = Vb50 = Vb60 = Vb70 = 512UL;
    Vb01 = Vb11 = Vb21 = Vb31 = Vb41 = Vb51 = Vb61 = Vb71 = 0;

    sph_u32 K0 = 512;
    sph_u32 K1 = 0;
    sph_u32 K2 = 0;
    sph_u32 K3 = 0;

    W00 = Vb00;
    W01 = Vb01;
    W10 = Vb10;
    W11 = Vb11;
    W20 = Vb20;
    W21 = Vb21;
    W30 = Vb30;
    W31 = Vb31;
    W40 = Vb40;
    W41 = Vb41;
    W50 = Vb50;
    W51 = Vb51;
    W60 = Vb60;
    W61 = Vb61;
    W70 = Vb70;
    W71 = Vb71;
    W80 = hash.h8[0];
    W81 = hash.h8[1];
    W90 = hash.h8[2];
    W91 = hash.h8[3];
    WA0 = hash.h8[4];
    WA1 = hash.h8[5];
    WB0 = hash.h8[6];
    WB1 = hash.h8[7];
    WC0 = 0x80;
    WC1 = 0;
    WD0 = 0;
    WD1 = 0;
    WE0 = 0;
    WE1 = 0x200000000000000;
    WF0 = 0x200;
    WF1 = 0;

    for (unsigned u = 0; u < 10; u ++) {
        BIG_ROUND;
    }

    hash.h8[0] ^= Vb00 ^ W00 ^ W80;
    hash.h8[1] ^= Vb01 ^ W01 ^ W81;
    hash.h8[2] ^= Vb10 ^ W10 ^ W90;
    hash.h8[3] ^= Vb11 ^ W11 ^ W91;
    hash.h8[4] ^= Vb20 ^ W20 ^ WA0;
    hash.h8[5] ^= Vb21 ^ W21 ^ WA1;
    hash.h8[6] ^= Vb30 ^ W30 ^ WB0;
    hash.h8[7] ^= Vb31 ^ W31 ^ WB1;

    }

    // hamsi

    {

    sph_u32 c0 = HAMSI_IV512[0], c1 = HAMSI_IV512[1], c2 = HAMSI_IV512[2], c3 = HAMSI_IV512[3];
    sph_u32 c4 = HAMSI_IV512[4], c5 = HAMSI_IV512[5], c6 = HAMSI_IV512[6], c7 = HAMSI_IV512[7];
    sph_u32 c8 = HAMSI_IV512[8], c9 = HAMSI_IV512[9], cA = HAMSI_IV512[10], cB = HAMSI_IV512[11];
    sph_u32 cC = HAMSI_IV512[12], cD = HAMSI_IV512[13], cE = HAMSI_IV512[14], cF = HAMSI_IV512[15];
    sph_u32 m0, m1, m2, m3, m4, m5, m6, m7;
    sph_u32 m8, m9, mA, mB, mC, mD, mE, mF;
    sph_u32 h[16] = { c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, cA, cB, cC, cD, cE, cF };

#define buf(u) hash.h1[i + u]
    for(int i = 0; i < 64; i += 8) {
        INPUT_BIG;
        P_BIG;
        T_BIG;
    }
#undef buf
#define buf(u) (u == 0 ? 0x80 : 0)
    INPUT_BIG;
    P_BIG;
    T_BIG;
#undef buf
#define buf(u) (u == 6 ? 2 : 0)
    INPUT_BIG;
    PF_BIG;
    T_BIG;

    for (unsigned u = 0; u < 16; u ++)
	hash.h4[u] = h[u];

    }

    // fugue

    {

    sph_u32 S00, S01, S02, S03, S04, S05, S06, S07, S08, S09;
    sph_u32 S10, S11, S12, S13, S14, S15, S16, S17, S18, S19;
    sph_u32 S20, S21, S22, S23, S24, S25, S26, S27, S28, S29;
    sph_u32 S30, S31, S32, S33, S34, S35;

    ulong fc_bit_count = (sph_u64) 64 << 3;

    S00 = S01 = S02 = S03 = S04 = S05 = S06 = S07 = S08 = S09 = S10 = S11 = S12 = S13 = S14 = S15 = S16 = S17 = S18 = S19 = 0;
    S20 = SPH_C32(0x8807a57e); S21 = SPH_C32(0xe616af75); S22 = SPH_C32(0xc5d3e4db); S23 = SPH_C32(0xac9ab027);
    S24 = SPH_C32(0xd915f117); S25 = SPH_C32(0xb6eecc54); S26 = SPH_C32(0x06e8020b); S27 = SPH_C32(0x4a92efd1);
    S28 = SPH_C32(0xaac6e2c9); S29 = SPH_C32(0xddb21398); S30 = SPH_C32(0xcae65838); S31 = SPH_C32(0x437f203f);
    S32 = SPH_C32(0x25ea78e7); S33 = SPH_C32(0x951fddd6); S34 = SPH_C32(0xda6ed11d); S35 = SPH_C32(0xe13e3567);

    FUGUE512_3((hash.h4[0x0]), (hash.h4[0x1]), (hash.h4[0x2]));
    FUGUE512_3((hash.h4[0x3]), (hash.h4[0x4]), (hash.h4[0x5]));
    FUGUE512_3((hash.h4[0x6]), (hash.h4[0x7]), (hash.h4[0x8]));
    FUGUE512_3((hash.h4[0x9]), (hash.h4[0xA]), (hash.h4[0xB]));
    FUGUE512_3((hash.h4[0xC]), (hash.h4[0xD]), (hash.h4[0xE]));
    FUGUE512_3((hash.h4[0xF]), as_uint2(fc_bit_count).y, as_uint2(fc_bit_count).x);

    // apply round shift if necessary
    int i;

    for (i = 0; i < 32; i ++) {
        ROR3;
        CMIX36(S00, S01, S02, S04, S05, S06, S18, S19, S20);
        SMIX(S00, S01, S02, S03);
    }
    for (i = 0; i < 13; i ++) {
        S04 ^= S00;
        S09 ^= S00;
        S18 ^= S00;
        S27 ^= S00;
        ROR9;
        SMIX(S00, S01, S02, S03);
        S04 ^= S00;
        S10 ^= S00;
        S18 ^= S00;
        S27 ^= S00;
        ROR9;
        SMIX(S00, S01, S02, S03);
        S04 ^= S00;
        S10 ^= S00;
        S19 ^= S00;
        S27 ^= S00;
        ROR9;
        SMIX(S00, S01, S02, S03);
        S04 ^= S00;
        S10 ^= S00;
        S19 ^= S00;
        S28 ^= S00;
        ROR8;
        SMIX(S00, S01, S02, S03);
    }
    S04 ^= S00;
    S09 ^= S00;
    S18 ^= S00;
    S27 ^= S00;

    hash.h4[0] = SWAP4(S01);
    hash.h4[1] = SWAP4(S02);
    hash.h4[2] = SWAP4(S03);
    hash.h4[3] = SWAP4(S04);
    hash.h4[4] = SWAP4(S09);
    hash.h4[5] = SWAP4(S10);
    hash.h4[6] = SWAP4(S11);
    hash.h4[7] = SWAP4(S12);
    hash.h4[8] = SWAP4(S18);
    hash.h4[9] = SWAP4(S19);
    hash.h4[10] = SWAP4(S20);
    hash.h4[11] = SWAP4(S21);
    hash.h4[12] = SWAP4(S27);
    hash.h4[13] = SWAP4(S28);
    hash.h4[14] = SWAP4(S29);
    hash.h4[15] = SWAP4(S30);

    }

    bool result = (hash.h8[3] <= target);
    if (result)
	output[atomic_inc(output+0xFF)] = SWAP4(gid);

    barrier(CLK_GLOBAL_MEM_FENCE); 
}

#endif // X13MODOLD

#endif // X13MOD_CL

/* $Id: blake.c 252 2011-06-07 17:55:14Z tp $ */
/*
 * BLAKE implementation.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

__constant static const sph_u64 BLAKE_IV512[8] = {
	SPH_C64(0x6A09E667F3BCC908), SPH_C64(0xBB67AE8584CAA73B),
	SPH_C64(0x3C6EF372FE94F82B), SPH_C64(0xA54FF53A5F1D36F1),
	SPH_C64(0x510E527FADE682D1), SPH_C64(0x9B05688C2B3E6C1F),
	SPH_C64(0x1F83D9ABFB41BD6B), SPH_C64(0x5BE0CD19137E2179)
};

#define Z00   0
#define Z01   1
#define Z02   2
#define Z03   3
#define Z04   4
#define Z05   5
#define Z06   6
#define Z07   7
#define Z08   8
#define Z09   9
#define Z0A   A
#define Z0B   B
#define Z0C   C
#define Z0D   D
#define Z0E   E
#define Z0F   F

#define Z10   E
#define Z11   A
#define Z12   4
#define Z13   8
#define Z14   9
#define Z15   F
#define Z16   D
#define Z17   6
#define Z18   1
#define Z19   C
#define Z1A   0
#define Z1B   2
#define Z1C   B
#define Z1D   7
#define Z1E   5
#define Z1F   3

#define Z20   B
#define Z21   8
#define Z22   C
#define Z23   0
#define Z24   5
#define Z25   2
#define Z26   F
#define Z27   D
#define Z28   A
#define Z29   E
#define Z2A   3
#define Z2B   6
#define Z2C   7
#define Z2D   1
#define Z2E   9
#define Z2F   4

#define Z30   7
#define Z31   9
#define Z32   3
#define Z33   1
#define Z34   D
#define Z35   C
#define Z36   B
#define Z37   E
#define Z38   2
#define Z39   6
#define Z3A   5
#define Z3B   A
#define Z3C   4
#define Z3D   0
#define Z3E   F
#define Z3F   8

#define Z40   9
#define Z41   0
#define Z42   5
#define Z43   7
#define Z44   2
#define Z45   4
#define Z46   A
#define Z47   F
#define Z48   E
#define Z49   1
#define Z4A   B
#define Z4B   C
#define Z4C   6
#define Z4D   8
#define Z4E   3
#define Z4F   D

#define Z50   2
#define Z51   C
#define Z52   6
#define Z53   A
#define Z54   0
#define Z55   B
#define Z56   8
#define Z57   3
#define Z58   4
#define Z59   D
#define Z5A   7
#define Z5B   5
#define Z5C   F
#define Z5D   E
#define Z5E   1
#define Z5F   9

#define Z60   C
#define Z61   5
#define Z62   1
#define Z63   F
#define Z64   E
#define Z65   D
#define Z66   4
#define Z67   A
#define Z68   0
#define Z69   7
#define Z6A   6
#define Z6B   3
#define Z6C   9
#define Z6D   2
#define Z6E   8
#define Z6F   B

#define Z70   D
#define Z71   B
#define Z72   7
#define Z73   E
#define Z74   C
#define Z75   1
#define Z76   3
#define Z77   9
#define Z78   5
#define Z79   0
#define Z7A   F
#define Z7B   4
#define Z7C   8
#define Z7D   6
#define Z7E   2
#define Z7F   A

#define Z80   6
#define Z81   F
#define Z82   E
#define Z83   9
#define Z84   B
#define Z85   3
#define Z86   0
#define Z87   8
#define Z88   C
#define Z89   2
#define Z8A   D
#define Z8B   7
#define Z8C   1
#define Z8D   4
#define Z8E   A
#define Z8F   5

#define Z90   A
#define Z91   2
#define Z92   8
#define Z93   4
#define Z94   7
#define Z95   6
#define Z96   1
#define Z97   5
#define Z98   F
#define Z99   B
#define Z9A   9
#define Z9B   E
#define Z9C   3
#define Z9D   C
#define Z9E   D
#define Z9F   0

#define Mx(r, i)    Mx_(Z ## r ## i)
#define Mx_(n)      Mx__(n)
#define Mx__(n)     M ## n

#define CSx(r, i)   CSx_(Z ## r ## i)
#define CSx_(n)     CSx__(n)
#define CSx__(n)    CS ## n

#define CS0   SPH_C32(0x243F6A88)
#define CS1   SPH_C32(0x85A308D3)
#define CS2   SPH_C32(0x13198A2E)
#define CS3   SPH_C32(0x03707344)
#define CS4   SPH_C32(0xA4093822)
#define CS5   SPH_C32(0x299F31D0)
#define CS6   SPH_C32(0x082EFA98)
#define CS7   SPH_C32(0xEC4E6C89)
#define CS8   SPH_C32(0x452821E6)
#define CS9   SPH_C32(0x38D01377)
#define CSA   SPH_C32(0xBE5466CF)
#define CSB   SPH_C32(0x34E90C6C)
#define CSC   SPH_C32(0xC0AC29B7)
#define CSD   SPH_C32(0xC97C50DD)
#define CSE   SPH_C32(0x3F84D5B5)
#define CSF   SPH_C32(0xB5470917)

#if SPH_64

#define CBx(r, i)   CBx_(Z ## r ## i)
#define CBx_(n)     CBx__(n)
#define CBx__(n)    CB ## n

#define CB0   SPH_C64(0x243F6A8885A308D3)
#define CB1   SPH_C64(0x13198A2E03707344)
#define CB2   SPH_C64(0xA4093822299F31D0)
#define CB3   SPH_C64(0x082EFA98EC4E6C89)
#define CB4   SPH_C64(0x452821E638D01377)
#define CB5   SPH_C64(0xBE5466CF34E90C6C)
#define CB6   SPH_C64(0xC0AC29B7C97C50DD)
#define CB7   SPH_C64(0x3F84D5B5B5470917)
#define CB8   SPH_C64(0x9216D5D98979FB1B)
#define CB9   SPH_C64(0xD1310BA698DFB5AC)
#define CBA   SPH_C64(0x2FFD72DBD01ADFB7)
#define CBB   SPH_C64(0xB8E1AFED6A267E96)
#define CBC   SPH_C64(0xBA7C9045F12C7F99)
#define CBD   SPH_C64(0x24A19947B3916CF7)
#define CBE   SPH_C64(0x0801F2E2858EFC16)
#define CBF   SPH_C64(0x636920D871574E69)

#endif

#if SPH_64

#define GB(m0, m1, c0, c1, a, b, c, d)   do { \
		a = SPH_T64(a + b + (m0 ^ c1)); \
		d = SPH_ROTR64(d ^ a, 32); \
		c = SPH_T64(c + d); \
		b = SPH_ROTR64(b ^ c, 25); \
		a = SPH_T64(a + b + (m1 ^ c0)); \
		d = SPH_ROTR64(d ^ a, 16); \
		c = SPH_T64(c + d); \
		b = SPH_ROTR64(b ^ c, 11); \
	} while (0)

#define ROUND_B(r)   do { \
		GB(Mx(r, 0), Mx(r, 1), CBx(r, 0), CBx(r, 1), V0, V4, V8, VC); \
		GB(Mx(r, 2), Mx(r, 3), CBx(r, 2), CBx(r, 3), V1, V5, V9, VD); \
		GB(Mx(r, 4), Mx(r, 5), CBx(r, 4), CBx(r, 5), V2, V6, VA, VE); \
		GB(Mx(r, 6), Mx(r, 7), CBx(r, 6), CBx(r, 7), V3, V7, VB, VF); \
		GB(Mx(r, 8), Mx(r, 9), CBx(r, 8), CBx(r, 9), V0, V5, VA, VF); \
		GB(Mx(r, A), Mx(r, B), CBx(r, A), CBx(r, B), V1, V6, VB, VC); \
		GB(Mx(r, C), Mx(r, D), CBx(r, C), CBx(r, D), V2, V7, V8, VD); \
		GB(Mx(r, E), Mx(r, F), CBx(r, E), CBx(r, F), V3, V4, V9, VE); \
	} while (0)

#endif

#if SPH_64

#define BLAKE_DECL_STATE64 \
	sph_u64 H0, H1, H2, H3, H4, H5, H6, H7; \
	sph_u64 S0, S1, S2, S3, T0, T1;

#define BLAKE_READ_STATE64(state)   do { \
		H0 = (state)->H[0]; \
		H1 = (state)->H[1]; \
		H2 = (state)->H[2]; \
		H3 = (state)->H[3]; \
		H4 = (state)->H[4]; \
		H5 = (state)->H[5]; \
		H6 = (state)->H[6]; \
		H7 = (state)->H[7]; \
		S0 = (state)->S[0]; \
		S1 = (state)->S[1]; \
		S2 = (state)->S[2]; \
		S3 = (state)->S[3]; \
		T0 = (state)->T0; \
		T1 = (state)->T1; \
	} while (0)

#define BLAKE_WRITE_STATE64(state)   do { \
		(state)->H[0] = H0; \
		(state)->H[1] = H1; \
		(state)->H[2] = H2; \
		(state)->H[3] = H3; \
		(state)->H[4] = H4; \
		(state)->H[5] = H5; \
		(state)->H[6] = H6; \
		(state)->H[7] = H7; \
		(state)->S[0] = S0; \
		(state)->S[1] = S1; \
		(state)->S[2] = S2; \
		(state)->S[3] = S3; \
		(state)->T0 = T0; \
		(state)->T1 = T1; \
	} while (0)

#define COMPRESS64   do { \
		V0 = H0; \
		V1 = H1; \
		V2 = H2; \
		V3 = H3; \
		V4 = H4; \
		V5 = H5; \
		V6 = H6; \
		V7 = H7; \
		V8 = S0 ^ CB0; \
		V9 = S1 ^ CB1; \
		VA = S2 ^ CB2; \
		VB = S3 ^ CB3; \
		VC = T0 ^ CB4; \
		VD = T0 ^ CB5; \
		VE = T1 ^ CB6; \
		VF = T1 ^ CB7; \
		ROUND_B(0); \
		ROUND_B(1); \
		ROUND_B(2); \
		ROUND_B(3); \
		ROUND_B(4); \
		ROUND_B(5); \
		ROUND_B(6); \
		ROUND_B(7); \
		ROUND_B(8); \
		ROUND_B(9); \
		ROUND_B(0); \
		ROUND_B(1); \
		ROUND_B(2); \
		ROUND_B(3); \
		ROUND_B(4); \
		ROUND_B(5); \
		H0 ^= S0 ^ V0 ^ V8; \
		H1 ^= S1 ^ V1 ^ V9; \
		H2 ^= S2 ^ V2 ^ VA; \
		H3 ^= S3 ^ V3 ^ VB; \
		H4 ^= S0 ^ V4 ^ VC; \
		H5 ^= S1 ^ V5 ^ VD; \
		H6 ^= S2 ^ V6 ^ VE; \
		H7 ^= S3 ^ V7 ^ VF; \
	} while (0)

#endif

__constant static const sph_u64 salt_zero_big[4] = { 0, 0, 0, 0 };

#ifdef __cplusplus
}
#endif

/* $Id: bmw.c 227 2010-06-16 17:28:38Z tp $ */
/*
 * BMW implementation.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

__constant static const sph_u64 BMW_IV512[] = {
	SPH_C64(0x8081828384858687), SPH_C64(0x88898A8B8C8D8E8F),
	SPH_C64(0x9091929394959697), SPH_C64(0x98999A9B9C9D9E9F),
	SPH_C64(0xA0A1A2A3A4A5A6A7), SPH_C64(0xA8A9AAABACADAEAF),
	SPH_C64(0xB0B1B2B3B4B5B6B7), SPH_C64(0xB8B9BABBBCBDBEBF),
	SPH_C64(0xC0C1C2C3C4C5C6C7), SPH_C64(0xC8C9CACBCCCDCECF),
	SPH_C64(0xD0D1D2D3D4D5D6D7), SPH_C64(0xD8D9DADBDCDDDEDF),
	SPH_C64(0xE0E1E2E3E4E5E6E7), SPH_C64(0xE8E9EAEBECEDEEEF),
	SPH_C64(0xF0F1F2F3F4F5F6F7), SPH_C64(0xF8F9FAFBFCFDFEFF)
};

#define XCAT(x, y)    XCAT_(x, y)
#define XCAT_(x, y)   x ## y

#define LPAR   (

#define I16_16    0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15
#define I16_17    1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16
#define I16_18    2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17
#define I16_19    3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18
#define I16_20    4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19
#define I16_21    5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20
#define I16_22    6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21
#define I16_23    7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22
#define I16_24    8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23
#define I16_25    9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24
#define I16_26   10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25
#define I16_27   11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26
#define I16_28   12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27
#define I16_29   13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28
#define I16_30   14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29
#define I16_31   15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30

#define M16_16    0,  1,  3,  4,  7, 10, 11
#define M16_17    1,  2,  4,  5,  8, 11, 12
#define M16_18    2,  3,  5,  6,  9, 12, 13
#define M16_19    3,  4,  6,  7, 10, 13, 14
#define M16_20    4,  5,  7,  8, 11, 14, 15
#define M16_21    5,  6,  8,  9, 12, 15, 16
#define M16_22    6,  7,  9, 10, 13,  0,  1
#define M16_23    7,  8, 10, 11, 14,  1,  2
#define M16_24    8,  9, 11, 12, 15,  2,  3
#define M16_25    9, 10, 12, 13,  0,  3,  4
#define M16_26   10, 11, 13, 14,  1,  4,  5
#define M16_27   11, 12, 14, 15,  2,  5,  6
#define M16_28   12, 13, 15, 16,  3,  6,  7
#define M16_29   13, 14,  0,  1,  4,  7,  8
#define M16_30   14, 15,  1,  2,  5,  8,  9
#define M16_31   15, 16,  2,  3,  6,  9, 10

#define ss0(x)    (((x) >> 1) ^ SPH_T32((x) << 3) \
                  ^ SPH_ROTL32(x,  4) ^ SPH_ROTL32(x, 19))
#define ss1(x)    (((x) >> 1) ^ SPH_T32((x) << 2) \
                  ^ SPH_ROTL32(x,  8) ^ SPH_ROTL32(x, 23))
#define ss2(x)    (((x) >> 2) ^ SPH_T32((x) << 1) \
                  ^ SPH_ROTL32(x, 12) ^ SPH_ROTL32(x, 25))
#define ss3(x)    (((x) >> 2) ^ SPH_T32((x) << 2) \
                  ^ SPH_ROTL32(x, 15) ^ SPH_ROTL32(x, 29))
#define ss4(x)    (((x) >> 1) ^ (x))
#define ss5(x)    (((x) >> 2) ^ (x))
#define rs1(x)    SPH_ROTL32(x,  3)
#define rs2(x)    SPH_ROTL32(x,  7)
#define rs3(x)    SPH_ROTL32(x, 13)
#define rs4(x)    SPH_ROTL32(x, 16)
#define rs5(x)    SPH_ROTL32(x, 19)
#define rs6(x)    SPH_ROTL32(x, 23)
#define rs7(x)    SPH_ROTL32(x, 27)

#define Ks(j)   SPH_T32((sph_u32)(j) * SPH_C32(0x05555555))

#define add_elt_s(mf, hf, j0m, j1m, j3m, j4m, j7m, j10m, j11m, j16) \
	(SPH_T32(SPH_ROTL32(mf(j0m), j1m) + SPH_ROTL32(mf(j3m), j4m) \
		- SPH_ROTL32(mf(j10m), j11m) + Ks(j16)) ^ hf(j7m))

#define expand1s_inner(qf, mf, hf, i16, \
		i0, i1, i2, i3, i4, i5, i6, i7, i8, \
		i9, i10, i11, i12, i13, i14, i15, \
		i0m, i1m, i3m, i4m, i7m, i10m, i11m) \
	SPH_T32(ss1(qf(i0)) + ss2(qf(i1)) + ss3(qf(i2)) + ss0(qf(i3)) \
		+ ss1(qf(i4)) + ss2(qf(i5)) + ss3(qf(i6)) + ss0(qf(i7)) \
		+ ss1(qf(i8)) + ss2(qf(i9)) + ss3(qf(i10)) + ss0(qf(i11)) \
		+ ss1(qf(i12)) + ss2(qf(i13)) + ss3(qf(i14)) + ss0(qf(i15)) \
		+ add_elt_s(mf, hf, i0m, i1m, i3m, i4m, i7m, i10m, i11m, i16))

#define expand1s(qf, mf, hf, i16) \
	expand1s_(qf, mf, hf, i16, I16_ ## i16, M16_ ## i16)
#define expand1s_(qf, mf, hf, i16, ix, iy) \
	expand1s_inner LPAR qf, mf, hf, i16, ix, iy)

#define expand2s_inner(qf, mf, hf, i16, \
		i0, i1, i2, i3, i4, i5, i6, i7, i8, \
		i9, i10, i11, i12, i13, i14, i15, \
		i0m, i1m, i3m, i4m, i7m, i10m, i11m) \
	SPH_T32(qf(i0) + rs1(qf(i1)) + qf(i2) + rs2(qf(i3)) \
		+ qf(i4) + rs3(qf(i5)) + qf(i6) + rs4(qf(i7)) \
		+ qf(i8) + rs5(qf(i9)) + qf(i10) + rs6(qf(i11)) \
		+ qf(i12) + rs7(qf(i13)) + ss4(qf(i14)) + ss5(qf(i15)) \
		+ add_elt_s(mf, hf, i0m, i1m, i3m, i4m, i7m, i10m, i11m, i16))

#define expand2s(qf, mf, hf, i16) \
	expand2s_(qf, mf, hf, i16, I16_ ## i16, M16_ ## i16)
#define expand2s_(qf, mf, hf, i16, ix, iy) \
	expand2s_inner LPAR qf, mf, hf, i16, ix, iy)

#if SPH_64

#define sb0(x)    (((x) >> 1) ^ SPH_T64((x) << 3) \
                  ^ SPH_ROTL64(x,  4) ^ SPH_ROTL64(x, 37))
#define sb1(x)    (((x) >> 1) ^ SPH_T64((x) << 2) \
                  ^ SPH_ROTL64(x, 13) ^ SPH_ROTL64(x, 43))
#define sb2(x)    (((x) >> 2) ^ SPH_T64((x) << 1) \
                  ^ SPH_ROTL64(x, 19) ^ SPH_ROTL64(x, 53))
#define sb3(x)    (((x) >> 2) ^ SPH_T64((x) << 2) \
                  ^ SPH_ROTL64(x, 28) ^ SPH_ROTL64(x, 59))
#define sb4(x)    (((x) >> 1) ^ (x))
#define sb5(x)    (((x) >> 2) ^ (x))
#define rb1(x)    SPH_ROTL64(x,  5)
#define rb2(x)    SPH_ROTL64(x, 11)
#define rb3(x)    SPH_ROTL64(x, 27)
#define rb4(x)    SPH_ROTL64(x, 32)
#define rb5(x)    SPH_ROTL64(x, 37)
#define rb6(x)    SPH_ROTL64(x, 43)
#define rb7(x)    SPH_ROTL64(x, 53)

#define Kb(j)   SPH_T64((sph_u64)(j) * SPH_C64(0x0555555555555555))

#define add_elt_b(mf, hf, j0m, j1m, j3m, j4m, j7m, j10m, j11m, j16) \
	(SPH_T64(SPH_ROTL64(mf(j0m), j1m) + SPH_ROTL64(mf(j3m), j4m) \
		- SPH_ROTL64(mf(j10m), j11m) + Kb(j16)) ^ hf(j7m))

#define expand1b_inner(qf, mf, hf, i16, \
		i0, i1, i2, i3, i4, i5, i6, i7, i8, \
		i9, i10, i11, i12, i13, i14, i15, \
		i0m, i1m, i3m, i4m, i7m, i10m, i11m) \
	SPH_T64(sb1(qf(i0)) + sb2(qf(i1)) + sb3(qf(i2)) + sb0(qf(i3)) \
		+ sb1(qf(i4)) + sb2(qf(i5)) + sb3(qf(i6)) + sb0(qf(i7)) \
		+ sb1(qf(i8)) + sb2(qf(i9)) + sb3(qf(i10)) + sb0(qf(i11)) \
		+ sb1(qf(i12)) + sb2(qf(i13)) + sb3(qf(i14)) + sb0(qf(i15)) \
		+ add_elt_b(mf, hf, i0m, i1m, i3m, i4m, i7m, i10m, i11m, i16))

#define expand1b(qf, mf, hf, i16) \
	expand1b_(qf, mf, hf, i16, I16_ ## i16, M16_ ## i16)
#define expand1b_(qf, mf, hf, i16, ix, iy) \
	expand1b_inner LPAR qf, mf, hf, i16, ix, iy)

#define expand2b_inner(qf, mf, hf, i16, \
		i0, i1, i2, i3, i4, i5, i6, i7, i8, \
		i9, i10, i11, i12, i13, i14, i15, \
		i0m, i1m, i3m, i4m, i7m, i10m, i11m) \
	SPH_T64(qf(i0) + rb1(qf(i1)) + qf(i2) + rb2(qf(i3)) \
		+ qf(i4) + rb3(qf(i5)) + qf(i6) + rb4(qf(i7)) \
		+ qf(i8) + rb5(qf(i9)) + qf(i10) + rb6(qf(i11)) \
		+ qf(i12) + rb7(qf(i13)) + sb4(qf(i14)) + sb5(qf(i15)) \
		+ add_elt_b(mf, hf, i0m, i1m, i3m, i4m, i7m, i10m, i11m, i16))

#define expand2b(qf, mf, hf, i16) \
	expand2b_(qf, mf, hf, i16, I16_ ## i16, M16_ ## i16)
#define expand2b_(qf, mf, hf, i16, ix, iy) \
	expand2b_inner LPAR qf, mf, hf, i16, ix, iy)

#endif

#define MAKE_W(tt, i0, op01, i1, op12, i2, op23, i3, op34, i4) \
	tt((M(i0) ^ H(i0)) op01 (M(i1) ^ H(i1)) op12 (M(i2) ^ H(i2)) \
	op23 (M(i3) ^ H(i3)) op34 (M(i4) ^ H(i4)))

#define Ws0    MAKE_W(SPH_T32,  5, -,  7, +, 10, +, 13, +, 14)
#define Ws1    MAKE_W(SPH_T32,  6, -,  8, +, 11, +, 14, -, 15)
#define Ws2    MAKE_W(SPH_T32,  0, +,  7, +,  9, -, 12, +, 15)
#define Ws3    MAKE_W(SPH_T32,  0, -,  1, +,  8, -, 10, +, 13)
#define Ws4    MAKE_W(SPH_T32,  1, +,  2, +,  9, -, 11, -, 14)
#define Ws5    MAKE_W(SPH_T32,  3, -,  2, +, 10, -, 12, +, 15)
#define Ws6    MAKE_W(SPH_T32,  4, -,  0, -,  3, -, 11, +, 13)
#define Ws7    MAKE_W(SPH_T32,  1, -,  4, -,  5, -, 12, -, 14)
#define Ws8    MAKE_W(SPH_T32,  2, -,  5, -,  6, +, 13, -, 15)
#define Ws9    MAKE_W(SPH_T32,  0, -,  3, +,  6, -,  7, +, 14)
#define Ws10   MAKE_W(SPH_T32,  8, -,  1, -,  4, -,  7, +, 15)
#define Ws11   MAKE_W(SPH_T32,  8, -,  0, -,  2, -,  5, +,  9)
#define Ws12   MAKE_W(SPH_T32,  1, +,  3, -,  6, -,  9, +, 10)
#define Ws13   MAKE_W(SPH_T32,  2, +,  4, +,  7, +, 10, +, 11)
#define Ws14   MAKE_W(SPH_T32,  3, -,  5, +,  8, -, 11, -, 12)
#define Ws15   MAKE_W(SPH_T32, 12, -,  4, -,  6, -,  9, +, 13)

#define MAKE_Qas   do { \
		qt[ 0] = SPH_T32(ss0(Ws0 ) + H( 1)); \
		qt[ 1] = SPH_T32(ss1(Ws1 ) + H( 2)); \
		qt[ 2] = SPH_T32(ss2(Ws2 ) + H( 3)); \
		qt[ 3] = SPH_T32(ss3(Ws3 ) + H( 4)); \
		qt[ 4] = SPH_T32(ss4(Ws4 ) + H( 5)); \
		qt[ 5] = SPH_T32(ss0(Ws5 ) + H( 6)); \
		qt[ 6] = SPH_T32(ss1(Ws6 ) + H( 7)); \
		qt[ 7] = SPH_T32(ss2(Ws7 ) + H( 8)); \
		qt[ 8] = SPH_T32(ss3(Ws8 ) + H( 9)); \
		qt[ 9] = SPH_T32(ss4(Ws9 ) + H(10)); \
		qt[10] = SPH_T32(ss0(Ws10) + H(11)); \
		qt[11] = SPH_T32(ss1(Ws11) + H(12)); \
		qt[12] = SPH_T32(ss2(Ws12) + H(13)); \
		qt[13] = SPH_T32(ss3(Ws13) + H(14)); \
		qt[14] = SPH_T32(ss4(Ws14) + H(15)); \
		qt[15] = SPH_T32(ss0(Ws15) + H( 0)); \
	} while (0)

#define MAKE_Qbs   do { \
		qt[16] = expand1s(Qs, M, H, 16); \
		qt[17] = expand1s(Qs, M, H, 17); \
		qt[18] = expand2s(Qs, M, H, 18); \
		qt[19] = expand2s(Qs, M, H, 19); \
		qt[20] = expand2s(Qs, M, H, 20); \
		qt[21] = expand2s(Qs, M, H, 21); \
		qt[22] = expand2s(Qs, M, H, 22); \
		qt[23] = expand2s(Qs, M, H, 23); \
		qt[24] = expand2s(Qs, M, H, 24); \
		qt[25] = expand2s(Qs, M, H, 25); \
		qt[26] = expand2s(Qs, M, H, 26); \
		qt[27] = expand2s(Qs, M, H, 27); \
		qt[28] = expand2s(Qs, M, H, 28); \
		qt[29] = expand2s(Qs, M, H, 29); \
		qt[30] = expand2s(Qs, M, H, 30); \
		qt[31] = expand2s(Qs, M, H, 31); \
	} while (0)

#define MAKE_Qs   do { \
		MAKE_Qas; \
		MAKE_Qbs; \
	} while (0)

#define Qs(j)   (qt[j])

#if SPH_64

#define Wb0    MAKE_W(SPH_T64,  5, -,  7, +, 10, +, 13, +, 14)
#define Wb1    MAKE_W(SPH_T64,  6, -,  8, +, 11, +, 14, -, 15)
#define Wb2    MAKE_W(SPH_T64,  0, +,  7, +,  9, -, 12, +, 15)
#define Wb3    MAKE_W(SPH_T64,  0, -,  1, +,  8, -, 10, +, 13)
#define Wb4    MAKE_W(SPH_T64,  1, +,  2, +,  9, -, 11, -, 14)
#define Wb5    MAKE_W(SPH_T64,  3, -,  2, +, 10, -, 12, +, 15)
#define Wb6    MAKE_W(SPH_T64,  4, -,  0, -,  3, -, 11, +, 13)
#define Wb7    MAKE_W(SPH_T64,  1, -,  4, -,  5, -, 12, -, 14)
#define Wb8    MAKE_W(SPH_T64,  2, -,  5, -,  6, +, 13, -, 15)
#define Wb9    MAKE_W(SPH_T64,  0, -,  3, +,  6, -,  7, +, 14)
#define Wb10   MAKE_W(SPH_T64,  8, -,  1, -,  4, -,  7, +, 15)
#define Wb11   MAKE_W(SPH_T64,  8, -,  0, -,  2, -,  5, +,  9)
#define Wb12   MAKE_W(SPH_T64,  1, +,  3, -,  6, -,  9, +, 10)
#define Wb13   MAKE_W(SPH_T64,  2, +,  4, +,  7, +, 10, +, 11)
#define Wb14   MAKE_W(SPH_T64,  3, -,  5, +,  8, -, 11, -, 12)
#define Wb15   MAKE_W(SPH_T64, 12, -,  4, -,  6, -,  9, +, 13)

#define MAKE_Qab   do { \
		qt[ 0] = SPH_T64(sb0(Wb0 ) + H( 1)); \
		qt[ 1] = SPH_T64(sb1(Wb1 ) + H( 2)); \
		qt[ 2] = SPH_T64(sb2(Wb2 ) + H( 3)); \
		qt[ 3] = SPH_T64(sb3(Wb3 ) + H( 4)); \
		qt[ 4] = SPH_T64(sb4(Wb4 ) + H( 5)); \
		qt[ 5] = SPH_T64(sb0(Wb5 ) + H( 6)); \
		qt[ 6] = SPH_T64(sb1(Wb6 ) + H( 7)); \
		qt[ 7] = SPH_T64(sb2(Wb7 ) + H( 8)); \
		qt[ 8] = SPH_T64(sb3(Wb8 ) + H( 9)); \
		qt[ 9] = SPH_T64(sb4(Wb9 ) + H(10)); \
		qt[10] = SPH_T64(sb0(Wb10) + H(11)); \
		qt[11] = SPH_T64(sb1(Wb11) + H(12)); \
		qt[12] = SPH_T64(sb2(Wb12) + H(13)); \
		qt[13] = SPH_T64(sb3(Wb13) + H(14)); \
		qt[14] = SPH_T64(sb4(Wb14) + H(15)); \
		qt[15] = SPH_T64(sb0(Wb15) + H( 0)); \
	} while (0)

#define MAKE_Qbb   do { \
		qt[16] = expand1b(Qb, M, H, 16); \
		qt[17] = expand1b(Qb, M, H, 17); \
		qt[18] = expand2b(Qb, M, H, 18); \
		qt[19] = expand2b(Qb, M, H, 19); \
		qt[20] = expand2b(Qb, M, H, 20); \
		qt[21] = expand2b(Qb, M, H, 21); \
		qt[22] = expand2b(Qb, M, H, 22); \
		qt[23] = expand2b(Qb, M, H, 23); \
		qt[24] = expand2b(Qb, M, H, 24); \
		qt[25] = expand2b(Qb, M, H, 25); \
		qt[26] = expand2b(Qb, M, H, 26); \
		qt[27] = expand2b(Qb, M, H, 27); \
		qt[28] = expand2b(Qb, M, H, 28); \
		qt[29] = expand2b(Qb, M, H, 29); \
		qt[30] = expand2b(Qb, M, H, 30); \
		qt[31] = expand2b(Qb, M, H, 31); \
	} while (0)

#define MAKE_Qb   do { \
		MAKE_Qab; \
		MAKE_Qbb; \
	} while (0)

#define Qb(j)   (qt[j])

#endif

#define FOLD(type, mkQ, tt, rol, mf, qf, dhf)   do { \
		type qt[32], xl, xh; \
		mkQ; \
		xl = qf(16) ^ qf(17) ^ qf(18) ^ qf(19) \
			^ qf(20) ^ qf(21) ^ qf(22) ^ qf(23); \
		xh = xl ^ qf(24) ^ qf(25) ^ qf(26) ^ qf(27) \
			^ qf(28) ^ qf(29) ^ qf(30) ^ qf(31); \
		dhf( 0) = tt(((xh <<  5) ^ (qf(16) >>  5) ^ mf( 0)) \
			+ (xl ^ qf(24) ^ qf( 0))); \
		dhf( 1) = tt(((xh >>  7) ^ (qf(17) <<  8) ^ mf( 1)) \
			+ (xl ^ qf(25) ^ qf( 1))); \
		dhf( 2) = tt(((xh >>  5) ^ (qf(18) <<  5) ^ mf( 2)) \
			+ (xl ^ qf(26) ^ qf( 2))); \
		dhf( 3) = tt(((xh >>  1) ^ (qf(19) <<  5) ^ mf( 3)) \
			+ (xl ^ qf(27) ^ qf( 3))); \
		dhf( 4) = tt(((xh >>  3) ^ (qf(20) <<  0) ^ mf( 4)) \
			+ (xl ^ qf(28) ^ qf( 4))); \
		dhf( 5) = tt(((xh <<  6) ^ (qf(21) >>  6) ^ mf( 5)) \
			+ (xl ^ qf(29) ^ qf( 5))); \
		dhf( 6) = tt(((xh >>  4) ^ (qf(22) <<  6) ^ mf( 6)) \
			+ (xl ^ qf(30) ^ qf( 6))); \
		dhf( 7) = tt(((xh >> 11) ^ (qf(23) <<  2) ^ mf( 7)) \
			+ (xl ^ qf(31) ^ qf( 7))); \
		dhf( 8) = tt(rol(dhf(4),  9) + (xh ^ qf(24) ^ mf( 8)) \
			+ ((xl << 8) ^ qf(23) ^ qf( 8))); \
		dhf( 9) = tt(rol(dhf(5), 10) + (xh ^ qf(25) ^ mf( 9)) \
			+ ((xl >> 6) ^ qf(16) ^ qf( 9))); \
		dhf(10) = tt(rol(dhf(6), 11) + (xh ^ qf(26) ^ mf(10)) \
			+ ((xl << 6) ^ qf(17) ^ qf(10))); \
		dhf(11) = tt(rol(dhf(7), 12) + (xh ^ qf(27) ^ mf(11)) \
			+ ((xl << 4) ^ qf(18) ^ qf(11))); \
		dhf(12) = tt(rol(dhf(0), 13) + (xh ^ qf(28) ^ mf(12)) \
			+ ((xl >> 3) ^ qf(19) ^ qf(12))); \
		dhf(13) = tt(rol(dhf(1), 14) + (xh ^ qf(29) ^ mf(13)) \
			+ ((xl >> 4) ^ qf(20) ^ qf(13))); \
		dhf(14) = tt(rol(dhf(2), 15) + (xh ^ qf(30) ^ mf(14)) \
			+ ((xl >> 7) ^ qf(21) ^ qf(14))); \
		dhf(15) = tt(rol(dhf(3), 16) + (xh ^ qf(31) ^ mf(15)) \
			+ ((xl >> 2) ^ qf(22) ^ qf(15))); \
	} while (0)

#define FOLDb   FOLD(sph_u64, MAKE_Qb, SPH_T64, SPH_ROTL64, M, Qb, dH)

__constant static const sph_u64 final_b[16] = {
	SPH_C64(0xaaaaaaaaaaaaaaa0), SPH_C64(0xaaaaaaaaaaaaaaa1),
	SPH_C64(0xaaaaaaaaaaaaaaa2), SPH_C64(0xaaaaaaaaaaaaaaa3),
	SPH_C64(0xaaaaaaaaaaaaaaa4), SPH_C64(0xaaaaaaaaaaaaaaa5),
	SPH_C64(0xaaaaaaaaaaaaaaa6), SPH_C64(0xaaaaaaaaaaaaaaa7),
	SPH_C64(0xaaaaaaaaaaaaaaa8), SPH_C64(0xaaaaaaaaaaaaaaa9),
	SPH_C64(0xaaaaaaaaaaaaaaaa), SPH_C64(0xaaaaaaaaaaaaaaab),
	SPH_C64(0xaaaaaaaaaaaaaaac), SPH_C64(0xaaaaaaaaaaaaaaad),
	SPH_C64(0xaaaaaaaaaaaaaaae), SPH_C64(0xaaaaaaaaaaaaaaaf)
};

