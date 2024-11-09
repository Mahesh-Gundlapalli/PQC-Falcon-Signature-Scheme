# falcon.py

This repository implements the signature scheme Falcon (https://falcon-sign.info/).
Falcon stands for **FA**st Fourier **L**attice-based **CO**mpact signatures over **N**TRU

## Content

This repository contains the following files (roughly in order of dependency):

1. [`common.py`](common.py) contains shared functions and constants
1. [`rng.py`](rng.py) implements a ChaCha20-based PRNG, useful for KATs (standalone)
1. [`samplerz.py`](samplerz.py) implements a Gaussian sampler over the integers (standalone)
1. [`fft_constants.py`](fft_constants.py) contains precomputed constants used in the FFT
1. [`ntt_constants.py`](ntt_constants.py) contains precomputed constants used in the NTT
1. [`fft.py`](fft.py) implements the FFT over R[x] / (x<sup>n</sup> + 1)
1. [`ntt.py`](ntt.py) implements the NTT over Z<sub>q</sub>[x] / (x<sup>n</sup> + 1)
1. [`ntrugen.py`](ntrugen.py) generate polynomials f,g,F,G in Z[x] / (x<sup>n</sup> + 1) such that f G - g F = q
1. [`ffsampling.py`](ffsampling.py) implements the fast Fourier sampling algorithm
1. [`falcon.py`](falcon.py) implements Falcon
1. [`test.py`](test.py) implements tests to check that everything is properly implemented


## How to use

1. Generate a secret key `sk = SecretKey(n)`
1. Generate the corresponding public key `pk = PublicKey(sk)`
1. Now we can sign messages:
   - To plainly sign a message m: `sig = sk.sign(m)`
   - To sign a message m with a pre-chosen 40-byte salt: `sig = sk.sign(m, salt)`
   Note that the message MUST be a byte array or byte string.
1. We can also verify signatures: `pk.verify(m, sig)`

Example in Python 3.6.9:

```
>>> import falcon
>>> sk = falcon.SecretKey(512)
>>> pk = falcon.PublicKey(sk)
>>> sk
Private key for n = 512:

f = [-1, 3, -2, -4, 5, -4, 4, -9, 5, 2, 6, 4, 4, 0, 1, -4, -4, -2, 2, -1, 7, -7, -2, -3, 7, -2, 6, -4, 2, -1, -1, 4, 0, -2, -1, -4, -1, -3, 1, 6, 4, -1, -3, 3, -6, 4, 3, -2, 2, 6, 0, -1, -3, 2, -5, -5, -4, 0, -4, 1, 3, -2, 10, 5, -5, -4, 1, 0, 0, 3, -1, 7, 5, -1, -2, 2, -3, -1, 4, 1, -2, -3, 6, 8, 2, 3, -7, 0, -1, -1, 3, 1, 10, -5, 5, -2, 2, -5, 4, -4, -8, 1, 3, 0, -5, 3, 6, 6, 3, 0, 2, 1, 3, 6, 1, 2, 0, 4, -3, 2, 7, 3, -1, -1, -6, 2, 3, 3, 0, 2, -5, -8, -1, 3, 1, -6, 0, 2, -4, 1, 1, 1, 1, 0, 0, 7, 11, 2, 3, 0, 1, 3, 5, -1, -4, 0, 3, -2, 3, 0, -3, 0, -2, -1, -2, -4, -3, 3, 4, 0, 0, -2, 4, -7, 5, -6, 3, -3, -2, -2, 2, 1, 3, 0, -6, -2, 5, 2, -1, -5, -3, 2, -2, 0, 3, -5, 1, -2, -5, 10, -3, 5, 3, 2, 1, -2, -1, 1, -6, -1, 0, -4, 7, 6, -1, -6, -2, -1, 6, -8, -2, 2, -3, 7, -3, 5, -3, -2, 1, -5, 3, 2, 9, -5, 4, 3, -2, 4, 7, 1, 1, 0, -4, 2, 0, 0, 3, 2, 4, 0, -3, 0, 5, 1, -1, -4, -7, 6, -3, -6, 8, -2, 7, -4, 2, 4, 0, -1, 7, 1, 3, -3, -7, 4, 8, 8, 1, 4, 4, 4, -1, -1, -12, 6, -2, 1, 0, 1, 3, 0, -3, -5, -6, -2, 3, 7, 0, -3, 1, 3, 2, -3, -1, 0, 1, -9, 0, 3, -3, -2, 4, 1, 6, -4, 6, -5, 0, -1, 1, 3, -3, 1, -2, 1, -3, -9, -1, -7, -5, -7, 6, -5, -1, 0, -1, -1, 1, 3, -1, -4, 6, 6, -3, 2, -8, 3, 2, -4, 0, -1, 1, -2, -3, -4, 2, 1, 9, 0, -1, 6, 1, -6, -1, 3, 0, -3, -6, 5, 0, 6, 7, 6, -9, 0, -5, 2, -1, 1, 2, 0, -5, 11, 0, -10, -5, -4, 3, 9, -1, -4, 4, 0, -4, -3, -2, -4, -3, -1, 0, -2, -2, 3, 0, 1, 7, -1, 1, -4, -5, 0, -7, 2, 3, 3, -3, -1, 0, 6, -8, 0, 3, 8, -1, 1, 4, 7, 1, 5, 0, 5, 1, 3, 2, -5, 2, -4, 5, -5, 3, -3, 5, 7, -9, 7, -5, 1, 3, 5, -5, 1, 7, -2, 1, -5, 7, -2, -4, -1, -2, -1, -3, -2, 1, -1, 0, 2, -3, -2, -3, 3, -9, -4, -5, 7, 1, -6, -1, -2, -4, -1, 2, 0, 1, 8, -1, 5, -11, -6, -1, -7, -4, -3, 1, 0, 9, -3, -9, 2, 2, -1, 6, 3, 9, -4, -1, -6, 3, -5, 1, 0, -4, -2]
g = [-1, -1, 1, 3, -1, -2, -1, 1, 0, -2, 4, -5, -1, 5, -2, -3, 0, 3, 2, 4, -1, -3, -6, -2, 1, -5, -8, 2, 4, 2, -2, -2, 6, 9, -2, -4, -4, 1, 0, 7, 0, 7, 6, 2, 1, 3, 2, 0, -1, -9, -5, -7, -1, -7, 8, 2, -4, -1, 8, 1, -2, 3, 2, 1, 3, 3, 5, 10, -4, -2, -4, -1, -6, -3, 10, -1, -1, -6, -5, 2, -1, 3, -4, 2, 6, -3, -1, 1, 2, 6, -4, -4, 3, -10, 7, 10, 4, -2, 0, 2, -1, -3, 4, 2, 0, 8, -5, 4, -3, 4, -2, 6, 6, -3, -2, 6, 2, 4, -3, -5, -2, -4, -3, 0, 2, 0, -3, 0, 1, 1, -3, 1, -3, 3, 2, 4, 2, -7, -2, -4, 0, -4, -2, -2, 2, 3, -5, 1, -1, -8, -3, 4, 9, -1, 3, 9, 2, 0, 5, -4, 3, 4, -2, 2, -1, -1, -1, -5, 2, -2, 1, 2, 0, 3, 9, 0, -7, 0, -4, 3, 2, -3, 1, 3, 0, 4, 1, 1, -2, 2, 1, 5, -6, -10, -1, -1, 1, -5, 3, 0, -3, -2, -2, 0, 2, 1, 3, 1, 7, 1, -10, -1, -3, 5, 0, 3, 4, -4, -4, -2, -6, 4, 5, -6, 2, -1, 2, 2, -9, -1, -3, -4, -1, -7, 5, 5, -4, -4, -8, -7, -2, -2, 2, 1, -11, -4, 6, 2, -3, -6, -1, -1, -4, 6, -4, -1, 1, 6, 2, 3, 3, -2, 1, 4, 7, -2, -5, 2, 1, -3, -1, 1, -3, -1, 6, 1, 6, -2, -1, 11, -1, -3, -3, 7, -1, -4, 4, 1, -2, 5, 2, -4, 3, -3, -9, -6, -1, -1, 1, 3, -3, 4, -4, -1, -6, -4, 4, -7, 1, 0, -1, -5, -6, 8, 0, 9, -7, -6, 0, -5, 5, 2, -5, -1, 3, 2, -3, 3, -2, 5, -4, 2, -1, 1, 0, 5, 0, -5, -8, -2, 0, -3, -6, 0, 0, -3, 6, -2, -2, -3, -4, -2, -2, 3, 4, 10, 1, 3, 1, -6, -3, -1, -3, 0, 2, 1, -1, 2, -1, 0, 2, 7, 3, -3, 0, 0, -3, -1, -5, 0, -2, 2, 3, 1, -3, -3, 5, -2, -4, -1, -2, 0, 1, 4, 4, -2, 1, 6, -3, 8, -8, 1, 1, -3, -3, -5, 0, 2, -2, -4, 2, -3, -4, 11, 1, -1, 4, -3, -3, -6, 6, -3, 7, 0, 6, -5, 3, -1, 3, 7, 10, -1, 5, 0, 1, 0, 6, 3, -8, 2, -3, 2, -7, -4, 0, -6, -4, -6, 0, -2, 3, -4, -3, -1, 5, -1, 6, -1, -4, -3, 0, -4, -4, -5, 5, 1, -1, 3, -1, -2, 10, 1, 1, 5, 2, -2, 1, 9, 9, -4, 0, 2, -10, 3, -2, -4, 1, 3, -3, 6, -7, -4, 3, -2, -1, 0, 1, -1, -8, 6, 2, 0, 1, -1, -6, 6, 2, 4, -2, 3, 7, 5]
F = [-43, 18, 14, 16, 0, -24, -5, 45, 55, -33, 27, 41, 7, 2, 28, -28, 13, 27, -19, 15, -9, 0, -6, 30, -64, 7, -25, -13, -7, 1, 6, -2, -11, -24, -11, -2, 3, -53, 14, 17, 17, 18, 41, 22, 5, -20, 10, 22, -19, -2, -16, -17, 37, -4, -3, -15, -26, 15, 32, -7, -10, 7, 17, -43, 47, -25, -79, -15, 3, -27, 4, -46, -8, 41, 18, 32, -28, 30, -3, 75, -18, 12, -10, 27, -18, -77, 20, 26, 27, -37, 30, -17, -3, 23, 38, 30, -14, 4, -21, 15, -20, -15, 16, -37, 4, 16, -3, -38, -11, 28, -18, -48, -25, 21, 15, 24, -20, 31, -37, 10, -18, 27, -46, 20, 78, -22, 32, -56, 69, -9, 22, 31, -22, -21, 19, 16, -66, -68, -1, -12, 39, -20, -21, -14, 42, -5, -50, -37, -21, -4, 14, -22, -8, 0, 25, 1, -3, -19, 23, 7, -7, 4, 11, 11, 7, 42, -1, 23, -46, 13, -6, 33, -30, -1, 20, 22, -20, -16, 8, -21, 6, -10, 31, -38, -20, 10, 31, -26, -5, -4, -26, -5, -42, -15, -12, 7, -1, 42, -2, -93, 7, -16, 10, 33, 5, 32, -2, 22, 12, -43, -20, 25, -6, -52, -2, -36, 16, -15, -24, 0, 12, -18, -8, -12, -43, 37, -33, -37, -11, -9, 33, -4, 26, 9, -28, -34, 40, 12, 22, 22, -48, 28, -5, 51, -5, 14, 1, 44, -12, -15, -28, 26, 38, -15, -44, 7, 16, -22, 1, 20, -25, -30, 27, -14, -3, 22, -14, -27, 11, 17, 36, -6, -14, -16, -7, -42, 3, 35, 11, -18, 8, 57, -24, -11, -18, -18, 13, -28, -19, -23, -8, 61, 2, -37, 25, -31, -43, -14, -39, 46, -36, -8, -20, -2, 9, -61, 19, -37, -42, -5, -5, -39, 6, 50, 14, 0, -15, 35, -12, -16, 11, -15, 0, 15, 9, 30, -15, -35, 22, -41, -20, -48, 5, -6, 3, -44, -8, -30, 0, 0, -29, 21, -15, 18, -47, 7, -3, 37, 21, 36, -18, -4, -47, -18, -33, 16, 1, 54, -40, 17, 4, 8, -52, -4, -24, -5, -44, 11, 11, -29, 50, -47, -17, -15, 9, 43, -14, 32, -43, -2, -35, 9, 12, 26, 27, -21, -1, -69, 6, -20, 55, -12, -31, 40, 5, 4, 0, 33, 7, -19, -14, 34, -51, 10, -6, 26, -49, -1, -1, 49, 27, -9, -2, -16, -26, 11, 22, -41, 17, 17, 36, 21, -23, -1, -25, -3, -49, 21, 5, 27, 32, 40, -1, 24, 4, 37, -31, 2, -41, -7, -4, 32, -15, -37, 1, -14, 33, -37, -2, -33, 3, 2, -6, 6, 54, 9, 21, -63, 16, -27, 37, -19, -27, -38, 19, 8, -6, -31, -23, 10, 31, -33, 13, -2, -28, 2, -30, -5, -85, 39, 4, 1, 4, 10, -19, 46, -42, 26, -27, -34, -52, 42, 20, 25, -16, -4, -61, -41, 2, 12, -60, 1, 44, 34, 1, -29, 45, -5, -35, -49, 29, 15]
G = [19, 23, 32, 25, -17, -41, -8, 5, 19, -2, -2, 9, -34, -9, -43, -20, -18, 53, 32, -12, -9, 11, -4, -2, 32, 14, 3, -19, 14, 12, 0, -7, -1, -19, -16, -28, -23, 24, -19, -6, -7, -40, 3, 23, -5, 15, 49, 26, -20, -6, -50, 11, 7, 2, 4, -51, -12, -10, -3, -25, -48, -1, -5, 12, 2, 15, 18, 15, 12, -12, 31, -20, -2, 18, 4, 35, -27, 10, -59, -7, 26, -16, -27, -14, 9, 3, -23, 13, -28, -32, 23, 30, 8, -44, -23, 4, 15, -13, 26, 9, 17, -15, 21, 10, -17, 27, 26, 29, 54, -16, -6, -29, -52, 7, -1, 19, 19, -21, 28, 21, -15, -23, -18, 13, -12, 21, -17, 7, 16, -30, -10, -28, -29, -5, -23, 7, 8, 12, -17, 8, 22, 18, 10, 15, 10, -35, -36, 31, 24, -10, -12, -50, -33, 5, 4, -1, -31, 27, -26, -26, -34, -19, 11, 43, 40, 1, 7, 2, -17, -24, 41, -52, -11, 1, -3, 0, 64, 27, 58, -6, -19, 6, -28, -28, -8, -19, 15, 10, -60, 33, -2, 11, -12, -26, -1, -19, -69, 43, 23, -12, -15, -37, -36, -25, 0, -11, -41, 14, 5, -8, -26, 54, 7, -7, 24, 21, -7, -19, -8, 37, 36, 11, -39, -17, 1, -7, -23, 28, 16, -52, 5, 2, -13, 5, 3, 85, -4, 64, -16, 8, 28, 0, 14, -41, -89, 26, 48, 19, 20, -29, 20, -43, -13, -36, 22, -26, 45, 13, 5, -43, -2, 49, -49, 4, -2, 20, -44, 13, 16, 2, -15, 22, -30, -26, -22, 15, 24, 3, 6, -15, -3, 16, -8, 17, -18, 62, 49, 25, 34, -6, 6, -26, 11, 1, -34, -35, 8, 16, 10, -37, -22, -54, -28, 16, 27, -4, -56, -9, -4, 24, -66, 4, -8, 8, -26, -26, 18, 25, 20, 17, -17, 27, -11, 7, 9, 29, 78, 13, 3, 4, -28, 20, 22, -47, 21, 18, -5, 46, -9, 16, 6, -29, 11, 2, -15, 18, -3, 23, -8, -21, 5, -23, 22, -31, 10, -10, -20, 36, 7, 40, -24, -32, -1, -51, -35, -9, 51, 21, -6, 9, -10, -34, -22, 21, 15, -44, 36, 35, 25, -15, 26, 16, 55, 5, -20, -49, -3, 45, 2, 24, -41, -24, 16, 13, -23, 20, -12, 10, 19, -8, -13, -23, 60, 7, -36, 28, -21, -9, 40, -17, -8, -18, 34, 10, -9, -34, 16, -38, -12, -49, -59, -26, -35, -4, 44, -1, 22, -37, 45, -21, 17, 2, 17, 45, -18, 9, 15, 52, 20, 6, -2, -42, -40, -6, 45, -13, 36, -62, -1, 42, 18, -44, -25, 40, 7, 41, -15, 16, 0, 21, 30, -48, -21, -30, -12, 30, -13, 2, 31, 24, 8, 2, -85, -30, -12, 4, 20, 9, 40, 32, -11, 29, -13, 23, 27, 23, 6, 0, 3, 16, 36, 21, -2, 26, 16, -3, 5, 44, -5, -29, -18, -6, -26, -57, -21, 20, 12, 14, -49, -10, -33, -33]

>>> pk
Public for n = 512:

h = [11258, 99, 3612, 4343, 4615, 3280, 9626, 5553, 6831, 9501, 7934, 1900, 4306, 6843, 3713, 3001, 9825, 1536, 4967, 6108, 9434, 7846, 1773, 7172, 2823, 7078, 215, 3008, 8899, 9242, 9662, 12076, 2734, 5012, 1759, 11331, 1851, 10068, 10187, 11363, 6803, 8462, 3920, 4702, 2237, 6995, 7948, 3700, 9427, 7590, 3588, 1096, 2770, 2121, 4949, 2043, 648, 4912, 7884, 7892, 4459, 7340, 1708, 4855, 9363, 1214, 2006, 2427, 11605, 228, 9744, 11736, 10757, 8643, 5430, 10002, 11884, 5626, 1993, 8256, 1091, 5809, 8750, 7028, 6181, 4334, 1252, 7461, 7356, 9514, 9788, 6370, 2830, 1172, 3250, 2610, 8698, 8651, 4249, 7356, 3481, 3248, 149, 6322, 415, 9786, 1925, 8416, 8619, 3086, 10294, 5697, 6601, 4526, 3563, 1352, 8155, 11121, 800, 4754, 8661, 7659, 8997, 1545, 11797, 4076, 8850, 1560, 12167, 10440, 839, 1367, 9813, 8093, 9563, 10580, 2131, 11100, 10058, 937, 3657, 5007, 9070, 8309, 8038, 270, 10028, 10351, 3204, 2371, 10735, 2807, 12058, 476, 5147, 7239, 6921, 8321, 12227, 8633, 11602, 8249, 7950, 8271, 8520, 7253, 5082, 3721, 6235, 9384, 3683, 9041, 6883, 3969, 8973, 9686, 7649, 7993, 5483, 8523, 5462, 11295, 4251, 10711, 8623, 877, 3964, 5962, 5459, 456, 10210, 10273, 4047, 5161, 2968, 10037, 7072, 10161, 7520, 3233, 2460, 7306, 1478, 646, 729, 447, 3461, 3245, 3187, 10248, 8679, 11078, 10318, 8186, 7124, 4743, 924, 8077, 10247, 1420, 2230, 4200, 4792, 4461, 2300, 6847, 2611, 1267, 3199, 1522, 10374, 5972, 3138, 8848, 3326, 4454, 7655, 2907, 8557, 1374, 2207, 8201, 5315, 12274, 6905, 7256, 8447, 6332, 5722, 2679, 4232, 2217, 11753, 11698, 11614, 2755, 8028, 7527, 11889, 7751, 3990, 3194, 222, 10262, 1406, 7239, 1933, 12050, 2053, 872, 10686, 10742, 8471, 8612, 12109, 9046, 2888, 4168, 10748, 6896, 4836, 1943, 3613, 7591, 4541, 9201, 1051, 11549, 6359, 5781, 2388, 1509, 10294, 7818, 551, 10476, 7727, 8851, 6147, 6095, 9743, 8700, 4665, 10745, 1952, 2805, 6061, 7853, 4705, 8595, 1592, 11445, 2590, 1650, 9961, 3737, 11051, 9887, 2772, 11871, 11319, 9401, 1864, 5714, 11982, 9738, 4580, 11265, 8081, 67, 4243, 10577, 3648, 7786, 6788, 2813, 11012, 9976, 12077, 1537, 3935, 11301, 2538, 215, 2733, 10539, 2763, 5294, 9568, 3485, 10441, 7602, 775, 2244, 11717, 1170, 104, 9203, 5808, 5258, 1146, 11534, 8510, 2003, 11878, 8545, 8198, 685, 8332, 8752, 4906, 2161, 2175, 1682, 9668, 1011, 4462, 3234, 5122, 1278, 4249, 3223, 664, 11909, 1209, 9220, 3807, 4837, 5755, 3983, 7586, 5626, 420, 12208, 11592, 5671, 4405, 3037, 10163, 4935, 3415, 3201, 216, 10983, 2983, 3616, 8690, 12141, 5822, 8661, 5107, 5321, 6412, 5504, 2712, 8636, 4084, 7866, 11042, 7286, 5051, 4779, 534, 7054, 8932, 3983, 7799, 9474, 11817, 6356, 5109, 9410, 241, 9274, 6930, 12070, 3064, 8381, 9603, 4256, 11911, 7747, 7515, 8671, 2193, 8670, 9500, 1367, 6482, 6189, 3910, 3029, 9258, 5464, 5524, 5478, 9161, 9644, 2343, 1831, 4510, 10859, 3527, 1213, 8282, 5793, 2328, 9176, 4137, 11772, 2886, 8185, 7817, 9541, 3531, 467, 11301, 207, 5633, 1084, 27, 8081, 11958, 9881, 10162, 5991, 11731, 10277, 11056, 844, 11277, 6358, 6460, 12143, 1394, 1016, 6089, 9789, 2980, 8148, 833, 2054, 12146, 1048, 6431, 6758, 9856, 7114, 9169, 6311, 1272, 3204]

>>> sig = sk.sign(b"Hello")
>>> sig
b'9\xe8%\xdf\xbb\xa2\x06TcH\xa6\x93\xb9q>\xe2\xec\x99\xf7\xc4\xe5>\xe8\x1dz\x9fX\x06\x14O\xdc\xd9\x97@\xe2\xee`\xc6\xf5j\x1a\xfb\xd02\xc8\x1d~\x12\xcao\xc8\x9e$\x85\xf7*N\x1dW\xbd\x01s\x12\x16r\x8c@5\xcd\x8f\xe3\xbf\x10\x1c\xd5\x14\xf2+T\xf9\x84P\xb4Vf_\x88*9\xda\xec\xa7K\x83e\x8b\x9cL\xd9\x1amz\xb4\x89:\x93\xfbZ\xbc;\'\xcf\x0f>B\xacY\xa2O\x90\xa6\xf3Yu1-\xc5\xa6W^6\xb9?\x86b\x13)*\x14\xc9\xbaW\xf71\xffea\x05\xc9\x9a\xfc\xa4\xe8\xf46\x1a\xec\xd2\x86\xdaM$!\xb6\x87\xaf\xe1\xc4\xc5/\xd3wm\x0blR;\xcd5\xd9C\x928\xa6\xcd\xf0\xcd\xe7\xf1\x15\xac\x85\x92\xe9\xe0\x83J\xe9\xd8\x8e?\x19\xac\xf4Z\xf6U\x8bRw\xd5N{L~W\xe569\xea\xdbE\x88\x98^<Y\x92#$\xdf\x93\x92\x9de":\x81&\x11W\xff\xa7\xa8A\xe4J\xa6\x19\x0e\xe8\xe9\xfeQ\xde\xee+\xac\xfe\xe1\xb8SJ\xd24\xa8\x89ZK,\xc1\xb1N\xac\xe2\xf9z\xc0\xe8"L\x16\xb5\x0b\x82 Q\xaeC\r\x9b\x94o\xe90#c\xc5\xe9\xb6\x0b\xe7\x11=.\xc5\x1d\x86\xe11\xa87\xcc\xf9\xa2\'\xf2B\xd2\xf1_\xe6;a\xbb\x0c\\W\x93\xc9ue\xd0\xe2\x0f\xb4i\x14[z\\\xdc\x9b8\xf0\xd3\x19\xc9\xae\xd6\xd0\xb0\xda\x92\xf9\x86\x16\xd1\xd0\xd2(v\x99XI\x1c\xf8A\x90`I\xd9:\xe6!\x9e\xeefn\x96c\xad\xd7\x1f6 \xb9\x14\xa6.\x89\xef\xcd\xa2\xe8U\xbaj\x9d\xcd\xa6\xf1\xf7[\x1a\xd2u\xe6\x88j\x1b\xd6\xc3\xfb\xacM\xae*\x9f\x1c &Lz\xa1\x1b\x95a\x15r\xa0\\\x16\x9b\x14\xc5sw\xef\x84X`\xcaT\x86\xc4\x9c\xffbjj\x9b\x06ap\x93(}wd\xa6\xe2\n\x86*wc\xcclI,\x13\xa9\x17\x9a\xbc\xca\x92g\xb3\x87r\xbc\xd2\xf6\xd9\x9f\xd9(\x9f%\x14\xcf\xc12\xc8e-\x8c\xf1ct\xf3\xdcj\xc3\xc0\xdb\x0e\tej\x90\x0e\x86\xe2\x85]\xa4\xf1\xec%\x03\x13\x00\x8e/\x17V\xe3\x1a\xd4\xac\x8b\xb7\xc2\xd7s>\x13L\xca\xbfC\xf1\xfb\x9f\x85\x1d\x9a\xdd\xf3]g_\xf96\xc1n\xd5"\x94\x8f\xf5\rXc(k\x84\x01\x8f q,\xd4\xa3c\xc7\x86(\xec\xf4\x00\xe7\xc7\t\x93\xaa\x86n\x04\xd3\t\xb1\xc0*\x16\x8c\xfa^n\x93T\xcc\xdd6\xb9=\x0b\x1f\x95l\xe2E\x08\x9b1\xb6$\xfc\x94\xf0u\xf2lt\x16\x86\xcc\xae\x1bI\xeb\x1a\x9f*kbY\x83\x851\xdb\xc17\x80?\xbe\t\xc6*\x0f)\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
>>> pk.verify(b"Hello", sig)
True
```

Upon first use, consider running `make test` to make sure that the code runs properly on your machine. You should obtain (the test battery for `n = 1024` may take a few minutes):

```
python3 test.py
Test Sig KATs       : OK
Test SamplerZ KATs  : OK         (46.887 msec / execution)

Test battery for n = 64
Test FFT            : OK          (0.907 msec / execution)
Test NTT            : OK          (0.957 msec / execution)
Test NTRUGen        : OK        (260.644 msec / execution)
Test ffNP           : OK          (5.024 msec / execution)
Test Compress       : OK          (0.184 msec / execution)
Test Signature      : OK          (6.266 msec / execution)

Test battery for n = 128
Test FFT            : OK          (1.907 msec / execution)
Test NTT            : OK          (2.137 msec / execution)
Test NTRUGen        : OK        (679.113 msec / execution)
Test ffNP           : OK         (11.589 msec / execution)
Test Compress       : OK           (0.36 msec / execution)
Test Signature      : OK         (11.882 msec / execution)

Test battery for n = 256
Test FFT            : OK          (4.298 msec / execution)
Test NTT            : OK          (5.014 msec / execution)
Test NTRUGen        : OK        (778.603 msec / execution)
Test ffNP           : OK         (26.182 msec / execution)
Test Compress       : OK          (0.758 msec / execution)
Test Signature      : OK         (23.865 msec / execution)

Test battery for n = 512
Test FFT            : OK          (9.455 msec / execution)
Test NTT            : OK          (9.997 msec / execution)
Test NTRUGen        : OK       (3578.415 msec / execution)
Test ffNP           : OK         (59.863 msec / execution)
Test Compress       : OK          (1.486 msec / execution)
Test Signature      : OK         (51.545 msec / execution)

Test battery for n = 1024
Test FFT            : OK         (20.706 msec / execution)
Test NTT            : OK         (22.937 msec / execution)
Test NTRUGen        : OK      (17707.189 msec / execution)
Test ffNP           : OK         (135.42 msec / execution)
Test Compress       : OK          (3.292 msec / execution)
Test Signature      : OK        (102.022 msec / execution)
```

<!--- ## Profiling

I included a makefile target to performing profiling on the code. If you type `make profile` on a Linux machine, you should obtain something along these lines:

![kcachegrind](https://tprest.github.io/images/kcachegrind_falcon.png)

Make sure you have `pyprof2calltree` and `kcachegrind` installed on your machine, or it will not work. --->


## Author

* **Thomas Prest** (thomas.prest@ens.fr)


<!---## Acknowledgements

Thank you to the following people for catching various bugs in the code:
- Dan Middleton
- Nadav Voloch
- Dekel Shiran
- Shlomi Dolev--->

## Disclaimer

This is not reference code. The reference code of Falcon is on https://falcon-sign.info/. This is work in progress. It is not to be considered secure or suitable for production. Also, I do not guarantee portability on Python 2.x.
However, this Python code is rather simple, so I hope that it will be helpful to people seeking to implement Falcon.

If you find errors or flaw, I will be very happy if you report them to me at the provided address.

## License

MIT
