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


#define WUpdate(i) { uint4 tmp1, tmp2, tmp3;						\
	tmp1 = (uint4) (W[(i+0)%4].y, W[(i+0)%4].z, W[(i+0)%4].w, W[(i+1)%4].x);	\
	tmp2 = (uint4) (W[(i+2)%4].y, W[(i+2)%4].z, W[(i+2)%4].w, W[(i+3)%4].x);	\
	tmp3 = (uint4) (W[(i+3)%4].z, W[(i+3)%4].w, 0, 0);				\
	W[(i+0)%4] += tmp2 + Wr2 (tmp1) + Wr1 (tmp3);					\
	tmp1 = (uint4) (0, 0, W[(i+0)%4].x, W[(i+0)%4].y);				\
	W[(i+0)%4] += Wr1 (tmp1);							\
	}

	WUpdate (0);
	RND(A,B,C,D,E,F,G,H, W[0].x+ K[15]);
	RND(H,A,B,C,D,E,F,G, W[0].y+ K[16]);
	RND(G,H,A,B,C,D,E,F, W[0].z+ K[17]);
	RND(F,G,H,A,B,C,D,E, W[0].w+ K[18]);

	WUpdate (1);
	RND(E,F,G,H,A,B,C,D, W[1].x+ K[19]);
	RND(D,E,F,G,H,A,B,C, W[1].y+ K[20]);
	RND(C,D,E,F,G,H,A,B, W[1].z+ K[21]);
	RND(B,C,D,E,F,G,H,A, W[1].w+ K[22]);

	WUpdate (2);
	RND(A,B,C,D,E,F,G,H, W[2].x+ K[23]);
	RND(H,A,B,C,D,E,F,G, W[2].y+ K[24]);
	RND(G,H,A,B,C,D,E,F, W[2].z+ K[25]);
	RND(F,G,H,A,B,C,D,E, W[2].w+ K[26]);

	WUpdate (3);
	RND(E,F,G,H,A,B,C,D, W[3].x+ K[27]);
	RND(D,E,F,G,H,A,B,C, W[3].y+ K[28]);
	RND(C,D,E,F,G,H,A,B, W[3].z+ K[29]);
	RND(B,C,D,E,F,G,H,A, W[3].w+ K[30]);

	WUpdate (0);
	RND(A,B,C,D,E,F,G,H, W[0].x+ K[31]);
	RND(H,A,B,C,D,E,F,G, W[0].y+ K[32]);
	RND(G,H,A,B,C,D,E,F, W[0].z+ K[33]);
	RND(F,G,H,A,B,C,D,E, W[0].w+ K[34]);

	WUpdate (1);
	RND(E,F,G,H,A,B,C,D, W[1].x+ K[35]);
	RND(D,E,F,G,H,A,B,C, W[1].y+ K[36]);
	RND(C,D,E,F,G,H,A,B, W[1].z+ K[37]);
	RND(B,C,D,E,F,G,H,A, W[1].w+ K[38]);

	WUpdate (2);
	RND(A,B,C,D,E,F,G,H, W[2].x+ K[39]);
	RND(H,A,B,C,D,E,F,G, W[2].y+ K[40]);
	RND(G,H,A,B,C,D,E,F, W[2].z+ K[41]);
	RND(F,G,H,A,B,C,D,E, W[2].w+ K[42]);

	WUpdate (3);
	RND(E,F,G,H,A,B,C,D, W[3].x+ K[43]);
	RND(D,E,F,G,H,A,B,C, W[3].y+ K[44]);
	RND(C,D,E,F,G,H,A,B, W[3].z+ K[45]);
	RND(B,C,D,E,F,G,H,A, W[3].w+ K[46]);

	WUpdate (0);
	RND(A,B,C,D,E,F,G,H, W[0].x+ K[47]);
	RND(H,A,B,C,D,E,F,G, W[0].y+ K[48]);
	RND(G,H,A,B,C,D,E,F, W[0].z+ K[49]);
	RND(F,G,H,A,B,C,D,E, W[0].w+ K[50]);

	WUpdate (1);
	RND(E,F,G,H,A,B,C,D, W[1].x+ K[51]);
	RND(D,E,F,G,H,A,B,C, W[1].y+ K[52]);
	RND(C,D,E,F,G,H,A,B, W[1].z+ K[53]);
	RND(B,C,D,E,F,G,H,A, W[1].w+ K[54]);

	WUpdate (2);
	RND(A,B,C,D,E,F,G,H, W[2].x+ K[55]);
	RND(H,A,B,C,D,E,F,G, W[2].y+ K[56]);
	RND(G,H,A,B,C,D,E,F, W[2].z+ K[57]);
	RND(F,G,H,A,B,C,D,E, W[2].w+ K[58]);

	WUpdate (3);
	RND(E,F,G,H,A,B,C,D, W[3].x+ K[59]);
	RND(D,E,F,G,H,A,B,C, W[3].y+ K[60]);
	RND(C,D,E,F,G,H,A,B, W[3].z+ K[61]);
	RND(B,C,D,E,F,G,H,A, W[3].w+ K[62]);
