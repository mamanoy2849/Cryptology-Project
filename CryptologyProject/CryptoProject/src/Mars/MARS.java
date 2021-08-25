package Mars;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
///////////////////////////NEW IMPORTS/////////////////
import algorithm.EllipticCurveAlgorithm;
import algorithm.PointProccessor;
import Entity.Bob;
import Entity.Alice;


public class MARS {

	/**
	 * Mars working with 128 bits blocks Mars IV Key is between 128 to 400 bits its
	 * mean that the key range is between 0 - 2^128, in our algorithm, we have 16
	 * Bytes that is 128 bits
	 **/

	/////////////////////////////// NEW///////////////////////
	public static byte[] iv;
	private static EllipticCurveAlgorithm ECC = new EllipticCurveAlgorithm();
	static PointProccessor PP = new PointProccessor();
	// mars key 128 bit
	public static String MarsKey;;
	public static byte[] AliceSignature;
	static KeyPair keyPair;// key pair
	private static SecretKeySpec skeySpec;

	private static int[] K;

	private static int[] s_box = { 0x09d0c479, 0x28c8ffe0, 0x84aa6c39, 0x9dad7287, 0x7dff9be3, 0xd4268361, 0xc96da1d4,
			0x7974cc93, 0x85d0582e, 0x2a4b5705, 0x1ca16a62, 0xc3bd279d, 0x0f1f25e5, 0x5160372f, 0xc695c1fb, 0x4d7ff1e4,
			0xae5f6bf4, 0x0d72ee46, 0xff23de8a, 0xb1cf8e83, 0xf14902e2, 0x3e981e42, 0x8bf53eb6, 0x7f4bf8ac, 0x83631f83,
			0x25970205, 0x76afe784, 0x3a7931d4, 0x4f846450, 0x5c64c3f6, 0x210a5f18, 0xc6986a26, 0x28f4e826, 0x3a60a81c,
			0xd340a664, 0x7ea820c4, 0x526687c5, 0x7eddd12b, 0x32a11d1d, 0x9c9ef086, 0x80f6e831, 0xab6f04ad, 0x56fb9b53,
			0x8b2e095c, 0xb68556ae, 0xd2250b0d, 0x294a7721, 0xe21fb253, 0xae136749, 0xe82aae86, 0x93365104, 0x99404a66,
			0x78a784dc, 0xb69ba84b, 0x04046793, 0x23db5c1e, 0x46cae1d6, 0x2fe28134, 0x5a223942, 0x1863cd5b, 0xc190c6e3,
			0x07dfb846, 0x6eb88816, 0x2d0dcc4a, 0xa4ccae59, 0x3798670d, 0xcbfa9493, 0x4f481d45, 0xeafc8ca8, 0xdb1129d6,
			0xb0449e20, 0x0f5407fb, 0x6167d9a8, 0xd1f45763, 0x4daa96c3, 0x3bec5958, 0xababa014, 0xb6ccd201, 0x38d6279f,
			0x02682215, 0x8f376cd5, 0x092c237e, 0xbfc56593, 0x32889d2c, 0x854b3e95, 0x05bb9b43, 0x7dcd5dcd, 0xa02e926c,
			0xfae527e5, 0x36a1c330, 0x3412e1ae, 0xf257f462, 0x3c4f1d71, 0x30a2e809, 0x68e5f551, 0x9c61ba44, 0x5ded0ab8,
			0x75ce09c8, 0x9654f93e, 0x698c0cca, 0x243cb3e4, 0x2b062b97, 0x0f3b8d9e, 0x00e050df, 0xfc5d6166, 0xe35f9288,
			0xc079550d, 0x0591aee8, 0x8e531e74, 0x75fe3578, 0x2f6d829a, 0xf60b21ae, 0x95e8eb8d, 0x6699486b, 0x901d7d9b,
			0xfd6d6e31, 0x1090acef, 0xe0670dd8, 0xdab2e692, 0xcd6d4365, 0xe5393514, 0x3af345f0, 0x6241fc4d, 0x460da3a3,
			0x7bcf3729, 0x8bf1d1e0, 0x14aac070, 0x1587ed55, 0x3afd7d3e, 0xd2f29e01, 0x29a9d1f6, 0xefb10c53, 0xcf3b870f,
			0xb414935c, 0x664465ed, 0x024acac7, 0x59a744c1, 0x1d2936a7, 0xdc580aa6, 0xcf574ca8, 0x040a7a10, 0x6cd81807,
			0x8a98be4c, 0xaccea063, 0xc33e92b5, 0xd1e0e03d, 0xb322517e, 0x2092bd13, 0x386b2c4a, 0x52e8dd58, 0x58656dfb,
			0x50820371, 0x41811896, 0xe337ef7e, 0xd39fb119, 0xc97f0df6, 0x68fea01b, 0xa150a6e5, 0x55258962, 0xeb6ff41b,
			0xd7c9cd7a, 0xa619cd9e, 0xbcf09576, 0x2672c073, 0xf003fb3c, 0x4ab7a50b, 0x1484126a, 0x487ba9b1, 0xa64fc9c6,
			0xf6957d49, 0x38b06a75, 0xdd805fcd, 0x63d094cf, 0xf51c999e, 0x1aa4d343, 0xb8495294, 0xce9f8e99, 0xbffcd770,
			0xc7c275cc, 0x378453a7, 0x7b21be33, 0x397f41bd, 0x4e94d131, 0x92cc1f98, 0x5915ea51, 0x99f861b7, 0xc9980a88,
			0x1d74fd5f, 0xb0a495f8, 0x614deed0, 0xb5778eea, 0x5941792d, 0xfa90c1f8, 0x33f824b4, 0xc4965372, 0x3ff6d550,
			0x4ca5fec0, 0x8630e964, 0x5b3fbbd6, 0x7da26a48, 0xb203231a, 0x04297514, 0x2d639306, 0x2eb13149, 0x16a45272,
			0x532459a0, 0x8e5f4872, 0xf966c7d9, 0x07128dc0, 0x0d44db62, 0xafc8d52d, 0x06316131, 0xd838e7ce, 0x1bc41d00,
			0x3a2e8c0f, 0xea83837e, 0xb984737d, 0x13ba4891, 0xc4f8b949, 0xa6d6acb3, 0xa215cdce, 0x8359838b, 0x6bd1aa31,
			0xf579dd52, 0x21b93f93, 0xf5176781, 0x187dfdde, 0xe94aeb76, 0x2b38fd54, 0x431de1da, 0xab394825, 0x9ad3048f,
			0xdfea32aa, 0x659473e3, 0x623f7863, 0xf3346c59, 0xab3ab685, 0x3346a90b, 0x6b56443e, 0xc6de01f8, 0x8d421fc0,
			0x9b0ed10c, 0x88f1a1e9, 0x54c1f029, 0x7dead57b, 0x8d7ba426, 0x4cf5178a, 0x551a7cca, 0x1a9a5f08, 0xfcd651b9,
			0x25605182, 0xe11fc6c3, 0xb6fd9676, 0x337b3027, 0xb7c8eb14, 0x9e5fd030, 0x6b57e354, 0xad913cf7, 0x7e16688d,
			0x58872a69, 0x2c2fc7df, 0xe389ccc6, 0x30738df1, 0x0824a734, 0xe1797a8b, 0xa4a8d57b, 0x5b5d193b, 0xc8a8309b,
			0x73f9a978, 0x73398d32, 0x0f59573e, 0xe9df2b03, 0xe8a5b6c8, 0x848d0704, 0x98df93c2, 0x720a1dc3, 0x684f259a,
			0x943ba848, 0xa6370152, 0x863b5ea3, 0xd17b978b, 0x6d9b58ef, 0x0a700dd4, 0xa73d36bf, 0x8e6a0829, 0x8695bc14,
			0xe35b3447, 0x933ac568, 0x8894b022, 0x2f511c27, 0xddfbcc3c, 0x006662b6, 0x117c83fe, 0x4e12b414, 0xc2bca766,
			0x3a2fec10, 0xf4562420, 0x55792e2a, 0x46f5d857, 0xceda25ce, 0xc3601d3b, 0x6c00ab46, 0xefac9c28, 0xb3c35047,
			0x611dfee3, 0x257c3207, 0xfdd58482, 0x3b14d84f, 0x23becb64, 0xa075f3a3, 0x088f8ead, 0x07adf158, 0x7796943c,
			0xfacabf3d, 0xc09730cd, 0xf7679969, 0xda44e9ed, 0x2c854c12, 0x35935fa3, 0x2f057d9f, 0x690624f8, 0x1cb0bafd,
			0x7b0dbdc6, 0x810f23bb, 0xfa929a1a, 0x6d969a17, 0x6742979b, 0x74ac7d05, 0x010e65c4, 0x86a3d963, 0xf907b5a0,
			0xd0042bd3, 0x158d7d03, 0x287a8255, 0xbba8366f, 0x096edc33, 0x21916a7b, 0x77b56b86, 0x951622f9, 0xa6c5e650,
			0x8cea17d1, 0xcd8c62bc, 0xa3d63433, 0x358a68fd, 0x0f9b9d3c, 0xd6aa295b, 0xfe33384a, 0xc000738e, 0xcd67eb2f,
			0xe2eb6dc2, 0x97338b02, 0x06c9f246, 0x419cf1ad, 0x2b83c045, 0x3723f18a, 0xcb5b3089, 0x160bead7, 0x5d494656,
			0x35f8a74b, 0x1e4e6c9e, 0x000399bd, 0x67466880, 0xb4174831, 0xacf423b2, 0xca815ab3, 0x5a6395e7, 0x302a67c5,
			0x8bdb446b, 0x108f8fa4, 0x10223eda, 0x92b8b48b, 0x7f38d0ee, 0xab2701d4, 0x0262d415, 0xaf224a30, 0xb3d88aba,
			0xf8b2c3af, 0xdaf7ef70, 0xcc97d3b7, 0xe9614b6c, 0x2baebff4, 0x70f687cf, 0x386c9156, 0xce092ee5, 0x01e87da6,
			0x6ce91e6a, 0xbb7bcc84, 0xc7922c20, 0x9d3b71fd, 0x060e41c6, 0xd7590f15, 0x4e03bb47, 0x183c198e, 0x63eeb240,
			0x2ddbf49a, 0x6d5cba54, 0x923750af, 0xf9e14236, 0x7838162b, 0x59726c72, 0x81b66760, 0xbb2926c1, 0x48a0ce0d,
			0xa6c0496d, 0xad43507b, 0x718d496a, 0x9df057af, 0x44b1bde6, 0x054356dc, 0xde7ced35, 0xd51a138b, 0x62088cc9,
			0x35830311, 0xc96efca2, 0x686f86ec, 0x8e77cb68, 0x63e1d6b8, 0xc80f9778, 0x79c491fd, 0x1b4c67f2, 0x58656dfb,
			0x50820371, 0x41811896, 0xe337ef7e, 0xd39fb119, 0xc97f0df6, 0x68fea01b, 0xa150a6e5, 0x55258962, 0xeb6ff41b,
			0xd7c9cd7a, 0xa619cd9e, 0xbcf09576, 0x2672c073, 0xf003fb3c, 0x4ab7a50b, 0x1484126a, 0x487ba9b1, 0xa64fc9c6,
			0xf6957d49, 0x38b06a75, 0xdd805fcd, 0x63d094cf, 0xf51c999e, 0x1aa4d343, 0xb8495294, 0xce9f8e99, 0xbffcd770,
			0xc7c275cc, 0x378453a7, 0x7b21be33, 0x397f41bd, 0x4e94d131, 0x92cc1f98, 0x5915ea51, 0x99f861b7, 0xc9980a88,
			0x1d74fd5f, 0xb0a495f8, 0x614deed0, 0xb5778eea, 0x5941792d, 0xfa90c1f8, 0x33f824b4, 0xc4965372, 0x3ff6d550,
			0x4ca5fec0, 0x8630e964, 0x5b3fbbd6, 0x7da26a48, 0xb203231a, 0x04297514, 0x2d639306, 0x2eb13149, 0x16a45272,
			0x532459a0, 0x8e5f4872, 0xf966c7d9, 0x07128dc0, 0x0d44db62, 0xafc8d52d, 0x06316131, 0xd838e7ce, 0x1bc41d00,
			0x3a2e8c0f, 0xea83837e, 0xb984737d, 0x13ba4891, 0xc4f8b949, 0xa6d6acb3, 0xa215cdce, 0x8359838b, 0x6bd1aa31,
			0xf579dd52, 0x21b93f93, 0xf5176781, 0x187dfdde, 0xe94aeb76, 0x2b38fd54, 0x431de1da, 0xab394825, 0x9ad3048f,
			0xdfea32aa, 0x659473e3, 0x623f7863, 0xf3346c59, 0xab3ab685, 0x3346a90b, 0x6b56443e, 0xc6de01f8, 0x8d421fc0,
			0x9b0ed10c, 0x88f1a1e9, 0x54c1f029, 0x7dead57b, 0x8d7ba426, 0x4cf5178a, 0x551a7cca, 0x1a9a5f08, 0xfcd651b9,
			0x25605182, 0xe11fc6c3, 0xb6fd9676, 0x337b3027, 0xb7c8eb14, 0x9e5fd030, 0x6b57e354, 0xad913cf7, 0x7e16688d,
			0x58872a69, 0x2c2fc7df, 0xe389ccc6, 0x30738df1, 0x0824a734, 0xe1797a8b, 0xa4a8d57b, 0x5b5d193b, 0xc8a8309b,
			0x73f9a978, 0x73398d32, 0x0f59573e, 0xe9df2b03, 0xe8a5b6c8, 0x848d0704, 0x98df93c2, 0x720a1dc3, 0x684f259a,
			0x943ba848, 0xa6370152, 0x863b5ea3, 0xd17b978b, 0x6d9b58ef, 0x0a700dd4, 0xa73d36bf, 0x8e6a0829, 0x8695bc14,
			0xe35b3447, 0x933ac568, 0x8894b022, 0x2f511c27, 0xddfbcc3c, 0x006662b6, 0x117c83fe, 0x4e12b414, 0xc2bca766,
			0x3a2fec10, 0xf4562420, 0x55792e2a, 0x46f5d857, 0xceda25ce, 0xc3601d3b, 0x6c00ab46, 0xefac9c28, 0xb3c35047,
			0x611dfee3, 0x257c3207, 0xfdd58482, 0x3b14d84f, 0x23becb64, 0xa075f3a3, 0x088f8ead, 0x07adf158, 0x7796943c,
			0xfacabf3d, 0xc09730cd, 0xf7679969, 0xda44e9ed, 0x2c854c12, 0x35935fa3, 0x2f057d9f, 0x690624f8, 0x1cb0bafd,
			0x7b0dbdc6, 0x810f23bb, 0xfa929a1a, 0x6d969a17, 0x6742979b, 0x74ac7d05, 0x010e65c4, 0x86a3d963, 0xf907b5a0,
			0xd0042bd3, 0x158d7d03, 0x287a8255, 0xbba8366f, 0x096edc33, 0x21916a7b, 0x77b56b86, 0x951622f9, 0xa6c5e650,
			0x8cea17d1, 0xcd8c62bc, 0xa3d63433, 0x358a68fd, 0x0f9b9d3c, 0xd6aa295b, 0xfe33384a, 0xc000738e, 0xcd67eb2f,
			0xe2eb6dc2, 0x97338b02, 0x06c9f246, 0x419cf1ad, 0x2b83c045, 0x3723f18a, 0xcb5b3089, 0x160bead7, 0x5d494656,
			0x35f8a74b, 0x1e4e6c9e, 0x000399bd, 0x67466880, 0xb4174831, 0xacf423b2, 0xca815ab3, 0x5a6395e7, 0x302a67c5,
			0x8bdb446b, 0x108f8fa4, 0x10223eda, 0x92b8b48b, 0x7f38d0ee, 0xab2701d4, 0x0262d415, 0xaf224a30, 0xb3d88aba,
			0xf8b2c3af, 0xdaf7ef70, 0xcc97d3b7, 0xe9614b6c, 0x2baebff4, 0x70f687cf, 0x386c9156, 0xce092ee5, 0x01e87da6,
			0x6ce91e6a, 0xbb7bcc84, 0xc7922c20, 0x9d3b71fd, 0x060e41c6, 0xd7590f15, 0x4e03bb47, 0x183c198e, 0x63eeb240,
			0x2ddbf49a, 0x6d5cba54, 0x923750af, 0xf9e14236, 0x7838162b, 0x59726c72, 0x81b66760, 0xbb2926c1, 0x48a0ce0d,
			0xa6c0496d, 0xad43507b, 0x718d496a, 0x9df057af, 0x44b1bde6, 0x054356dc, 0xde7ced35, 0xd51a138b, 0x62088cc9,
			0x35830311, 0xc96efca2, 0x686f86ec, 0x8e77cb68, 0x63e1d6b8, 0xc80f9778, 0x79c491fd, 0x1b4c67f2, };

	private static int rotl(int val, int pas) {
		return (val << pas) | (val >>> (32 - pas));
	}

	@SuppressWarnings("unused")
	private static int rotr(int val, int pas) {
		return (val >>> pas) | (val << (32 - pas));
	}

	private static int[] expandKey(byte[] key) {
		int n = key.length / 4;
		int[] tmp = new int[40];
		int[] data = new int[n];

		for (int i = 0; i < data.length; i++)
			data[i] = 0;

		int off = 0;
		for (int i = 0; i < data.length; i++) {
			data[i] = ((key[off++] & 0xff)) | ((key[off++] & 0xff) << 8) | ((key[off++] & 0xff) << 16)
					| ((key[off++] & 0xff) << 24);
		}

		int[] T = new int[15];
		for (int i = 0; i < T.length; i++) {
			if (i < data.length)
				T[i] = data[i];
			else if (i == data.length)
				T[i] = n;
			else
				T[i] = 0;
		}

		for (int j = 0; j < 4; j++) {
			for (int i = 0; i < T.length; i++)
				T[i] = T[i] ^ (rotl(T[Math.abs(i - 7 % 15)] ^ T[Math.abs(i - 2 % 15)], 3) ^ (4 * i + j));
			for (int c = 0; c < 4; c++)
				for (int i = 0; i < T.length; i++)
					T[i] = T[i] + rotl(s_box[(int) (T[Math.abs(i - 1 % 15)] & 0x000001ff)], 9);
			for (int i = 0; i <= 9; i++)
				tmp[10 * j + i] = T[4 * i % 15];
		}

		int[] B = { 0xa4a8d57b, 0x5b5d193b, 0xc8a8309b, 0x73f9a978 };
		int j, w, m, r, p;
		for (int i = 5; i <= 35; i++) {
			j = tmp[i] & 0x00000003;
			w = tmp[i] | 0x00000003;
			m = generateMask(w);
			r = tmp[i - 1] & 0x0000001f;
			p = rotl(B[j], r);
			tmp[i] = w ^ (p & m);
		}

		return tmp;
	}

	private static int generateMask(int x) {
		int m;

		m = (~x ^ (x >>> 1)) & 0x7fffffff;
		m &= (m >> 1) & (m >> 2);
		m &= (m >> 3) & (m >> 6);

		if (m == 0)
			return 0;

		m <<= 1;
		m |= (m << 1);
		m |= (m << 2);
		m |= (m << 4);

		m |= (m << 1) & ~x & 0x80000000;

		return m & 0xfffffffc;

	}

	public static byte[] encrypt(byte[] in, byte[] key) throws Exception {
		int lenght = 0;
		byte[] padding = new byte[1];
		K = expandKey(key);
		int i;
		lenght = 16 - in.length % 16;
		padding = new byte[lenght];
		padding[0] = (byte) 0x80;

		for (i = 1; i < lenght; i++)
			padding[i] = 0;

		byte[] tmp = new byte[in.length + lenght];
		byte[] bloc = new byte[16];
		int count = 0;

		for (i = 0; i < in.length + lenght; i++) {
			if (i > 0 && i % 16 == 0) {
				// bloc = encryptBloc(bloc);
				bloc = encryptCipher(bloc, K);
				System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);
			}
			if (i < in.length)
				bloc[i % 16] = in[i];
			else {
				bloc[i % 16] = padding[count % 16];
				count++;
			}
		}
		if (bloc.length == 16) {
			// bloc = encryptBloc(bloc);
			bloc = encryptCipher(bloc, K);
			System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);
		}

		return tmp;
	}

	public static byte[] decrypt(byte[] in, byte[] Key) throws Exception {
		byte[] tmp = new byte[in.length];
		byte[] bloc = new byte[16];
		K = expandKey(Key);
		int i;
		for (i = 0; i < in.length; i++) {
			if (i > 0 && i % 16 == 0) {
				// bloc = decryptBloc(bloc);
				bloc = decryptCipher(bloc, K);
				System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);
			}
			if (i < in.length)
				bloc[i % 16] = in[i];
		}
		// bloc = decryptBloc(bloc);
		bloc = decryptCipher(bloc, K);
		System.arraycopy(bloc, 0, tmp, i - 16, bloc.length);

		tmp = deletePadding(tmp);

		return tmp;
	}

	private static byte[] deletePadding(byte[] input) {
		int count = 0;

		int i = input.length - 1;
		while (input[i] == 0) {
			count++;
			i--;
		}

		byte[] tmp = new byte[input.length - count - 1];
		System.arraycopy(input, 0, tmp, 0, tmp.length);
		return tmp;
	}

/////////////////////////////////////NEW!!/////////////////////////

	public static void main(String[] args) throws Exception {
		iv = new byte[] { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF };
		System.out.println("BASE: " + ECC.base);

		// Generate public and private keys
		// Agreed Base Point --> ECC.Base (10,96)

		// Now Bob and Alice have both private and public keys
		Alice Alice = new Alice();
		Bob Bob = new Bob();
		Bob.setPublicKey(ECC.generatePublicKey(Long.parseLong(Bob.getPrivateKeyBob())));
		System.out.println("Bob's public key: " + Bob.getPublicKey());
		Alice.setPublicKey(ECC.generatePublicKey(Long.parseLong(Alice.getPrivateKeyAlice())));
		System.out.println("Alic's public key: " + Alice.getPublicKey());
		
		//generete Random MarsKey
		   byte[] array = new byte[16]; // length is bounded by 16
		    new Random().nextBytes(array);
		    MarsKey = new String(array, Charset.forName("UTF-8"));
		    System.out.println("MARS KEY IS: " + MarsKey);
		
		
//ALICE'S SIDE
		// open an image and create 128 bit block in each cell
		// Read all pixels to block arrays of 128 bit to matrix data[all pixels divide
		// 128][128]
		int k = 0;
		BufferedImage bImage = ImageIO.read(new File("example.jpg"));
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ImageIO.write(bImage, "jpg", bos);
		byte[] pixels = bos.toByteArray();
		byte[][] data = new byte[pixels.length / 16][16];
		for (int i = 0; i < pixels.length / 16; i++) {
			for (int j = 0; j < 16; j++) {
				data[i][j] = pixels[k++];
			}
		}

		byte[][] encryptedString = new byte[pixels.length / 16][16];

		// See Encryption as an output.txt
		createTxtFile("Encrypted Text File");

		// Encrypted blocks of 128 bits
		for (int i = 0; i < pixels.length / 16; i++) {
			encryptedString[i] = encrypt(data[i], MarsKey.getBytes());
			writeToFile("Encrypted Text File", encryptedString[i]);
		}

		
		// ElGAMAL Key Encryption --> Alice's Side and set it on Bobs site (publish)
		//send bob the encrypted Mars key!!
		Bob.setKey(ECC.encrypt(MarsKey.getBytes(), Bob.getPublicKey(), Long.parseLong(Alice.getPrivateKeyAlice())));
		//now, Alice will sign the encrypted mars key that she encrypted using her private key
		AliceSignature = createDigitalSignature(Bob.getKey());
		//publish Alice's signature
		Bob.setSignature(AliceSignature);
		System.out.println("Signature for sending Bob is: " + Bob.getSignature());

		
		
//BOB'S SIDE
		
		// ElGAMAL Alice's Signatur - Decryption --> Bob's side
		byte[] bobsKey = elGamalAliceDecription(AliceSignature, Bob.getKey(), Bob.getPrivateKeyBob());
		System.out.println("Key Of Alice After Decryption: " + bobsKey);

		// Decrypt Data using bobsKey(MarsKey)
		byte[][] decryptedString = new byte[pixels.length / 16][16];
		for (int i = 0; i < pixels.length / 16; i++) {
			decryptedString[i] = decrypt(encryptedString[i], bobsKey);
		}

		// Create a decrypted image
		k = 0;
		byte[] bytes = new byte[pixels.length];
		for (int i = 0; i < pixels.length / 16; i++) {
			for (int j = 0; j < 16; j++) {
				if (k < pixels.length) {
					bytes[k++] = decryptedString[i][j];
				}
			}
		}
		// Output the decrypted image
		ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
		BufferedImage bImage2 = ImageIO.read(bis);
		if (bImage2 == null)
			System.out.println("Decrypt Failed!!");
		else {
			ImageIO.write(bImage2, "jpg", new File("output2.jpg"));
			System.out.println("image created");
		}

	}

	private static void writeToFile(String name, byte[] input) {

		File file = new File(name + ".txt");

		try (FileOutputStream fos = new FileOutputStream(file)) {
			fos.write(input);
			return;
		} catch (IOException e) {
			e.printStackTrace();
			return;
		}
	}

	private static void createTxtFile(String name) {
		try {
			File myObj = new File(name + ".txt");
			if (myObj.createNewFile()) {
				System.out.println("File created: " + myObj.getName());
				return;
			} else {
				System.out.println("File already exists.");
				return;
			}
		} catch (IOException e) {
			System.out.println("An error occurred.");
			e.printStackTrace();
		}
		return;
	}

	//key is the signature , data is the key that alice signs up and Bobskey is the private key of bob
	public static byte[] elGamalAliceDecription(byte[] key ,byte[] data, String BobsKey)
			throws SignatureException, UnsupportedEncodingException {
		/*
		 * That function takes Alice's encrypted key and decrypts it with Bob's private
		 * key
		 */
		// Verify Signature
		try {
			if (verifySignature(key,data))
				return ECC.decrypt(data, Long.parseLong(BobsKey));

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			// Not GOOD!!
		}
		return "NOT SIGN IN BY ALICE!!".getBytes();

	}

	private static byte[] createDigitalSignature(byte[] key) throws Exception {
		// Not a real private key! Replace with your private key!

		// Remove markers and new line characters in private key
		// calling getKeyPair() method and assigning in keypair
		keyPair = getKeyPair();
		Signature privateSignature = Signature.getInstance("SHA256withRSA");
		privateSignature.initSign(keyPair.getPrivate());
		// The data we want too signature on!!
		privateSignature.update(key);
		// sign the data!
		byte[] s = privateSignature.sign();
		return s;
	}

	private static boolean verifySignature(byte[] key, byte[] data)
			throws NoSuchAlgorithmException, SignatureException, UnsupportedEncodingException {
		Signature publicSignatur = Signature.getInstance("SHA256withRSA");
		try {
			publicSignatur.initVerify(keyPair.getPublic());
			publicSignatur.update(data);
			return publicSignatur.verify(key);
		} catch (InvalidKeyException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			return false;
		}
	}

	private static KeyPair getKeyPair() throws NoSuchAlgorithmException {

		// creating the object of KeyPairGenerator
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");

		// initializing with 1024
		kpg.initialize(1024);

		// returning the key pairs
		return kpg.genKeyPair();
	}

	private static byte[] getRawKey(byte[] seed) throws Exception {
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		sr.setSeed(seed);
		kgen.init(128, sr); // 192 and 256 bits may not be available
		SecretKey skey = kgen.generateKey();
		byte[] raw = skey.getEncoded();
		return raw;
	}

	public static byte[] int2byte(int[] src) {
		int srcLength = src.length;
		byte[] dst = new byte[srcLength << 2];

		for (int i = 0; i < srcLength; i++) {
			int x = src[i];
			int j = i << 2;
			dst[j++] = (byte) ((x >>> 0) & 0xff);
			dst[j++] = (byte) ((x >>> 8) & 0xff);
			dst[j++] = (byte) ((x >>> 16) & 0xff);
			dst[j++] = (byte) ((x >>> 24) & 0xff);
		}
		return dst;
	}

	public static long bytesToLong(byte[] bytes) {
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.put(bytes, 0, bytes.length);
		buffer.flip();// need flip
		return buffer.getLong();
	}

	private static byte[] encryptCipher(byte[] data, int[] key) throws Exception {
		byte[] rawKey = int2byte(key);
		rawKey = getRawKey(rawKey);

		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		skeySpec = new SecretKeySpec(rawKey, "AES");
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("AES/CFB/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);

		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
//encryped the data!
		byte[] encrypted = cipher.doFinal(data);
		return encrypted;
	}

	private static byte[] decryptCipher(byte[] encrypted, int[] key) throws Exception {

		byte[] rawKey = int2byte(key);
		rawKey = getRawKey(rawKey);
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		SecretKeySpec skeySpec = new SecretKeySpec(rawKey, "AES");
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("AES/CFB/NoPadding");
			cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}

		byte[] decrypted = cipher.doFinal(encrypted);
		return decrypted;
	}
}