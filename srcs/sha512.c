/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sha512.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/25 02:45:31 by sclolus           #+#    #+#             */
/*   Updated: 2018/07/25 20:16:31 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

static const uint64_t	g_sha512_constants[80] = {
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
	0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
	0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
	0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
	0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
	0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
	0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
	0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
	0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
	0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
	0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
	0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
	0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

INLINE static void		sha512_init(uint64_t *states)
{
	states[A] = 0x6a09e667f3bcc908;
	states[B] = 0xbb67ae8584caa73b;
	states[C] = 0x3c6ef372fe94f82b;
	states[D] = 0xa54ff53a5f1d36f1;
	states[E] = 0x510e527fade682d1;
	states[F] = 0x9b05688c2b3e6c1f;
	states[G] = 0x1f83d9abfb41bd6b;
	states[H] = 0x5be0cd19137e2179;
}

INLINE static void		sha512_padding(uint8_t *clear, uint8_t *last_blocks
									   , uint64_t len)
{
	__uint128_t	printed_len;

	ft_bzero(last_blocks, 256);
	ft_memcpy(last_blocks, clear + len - len % 128, len % 128);
	*((uint8_t*)last_blocks + len % 128) |= 0x80;
	printed_len = len * 8;
	if (ft_get_endianness())
		printed_len = ((__uint128_t)(swap_int64((uint64_t)printed_len)) << 64);
	((__uint128_t*)(void*)last_blocks)[7 + 8 * ((len % 128) > 128 - 17)] = printed_len;
	print_memory(last_blocks, 256);
	assert(!memcmp(last_blocks, clear + len - len % 128, len % 128));
}


INLINE static void	init_message_schedule_array(uint64_t *array, uint64_t *block)
{
	uint64_t	i;
	uint64_t	tmp_1;
	uint64_t	tmp_2;

	ft_bzero(array, 80 * sizeof(uint64_t)); //should be removed
	i = 0;
	ft_memcpy(array, block, 16 * sizeof(uint64_t));
	if (ft_get_endianness())
		while (i < 16)
		{
			array[i] = swap_int64(array[i]);
			i++;
		}
	i = 16;
	while (i < 80)
	{
		tmp_1 = right_rotate_64(array[i - 15], 1)
			^ right_rotate_64(array[i - 15], 8)
			^ (array[i - 15] >> 7);
		tmp_2 = right_rotate_64(array[i - 2], 19)
			^ right_rotate_64(array[i - 2], 61)
			^ (array[i - 2] >> 6);
		array[i] = array[i - 16] + tmp_1 + array[i - 7] + tmp_2;
		i++;
	}
	printf("array-\n");
	print_memory(array, 80 * 8);
	printf("end-array-\n");
}

INLINE static void	sha512_round(uint64_t *states, uint64_t *message_schedule_array)
{
	uint64_t	i;
	uint64_t	s1;
	uint64_t	s0;
	uint64_t	ch;
	uint64_t	tmp1;
	uint64_t	maj;
	uint64_t	tmp2;

	i = 0;
	while (i < 80)
	{
		s1 = (right_rotate_64(states[E], 14)) ^ (right_rotate_64(states[E], 18))
			^ (right_rotate_64(states[E], 41));
		ch = (states[E] & states[F]) ^ (~(states[E]) & states[G]);
		tmp1 = states[H] + s1 + ch + g_sha512_constants[i] + message_schedule_array[i];
		s0 = (right_rotate_64(states[A], 28))
			^ (right_rotate_64(states[A], 34))
			^ (right_rotate_64(states[A], 39));
		maj = (states[A] & states[B]) ^ (states[A] & states[C]) ^ (states[B] & states[C]);
		tmp2 = s0 + maj;
		states[H] = states[G];
		states[G] = states[F];
		states[F] = states[E];
		states[E] = states[D] + tmp1;
		states[D] = states[C];
		states[C] = states[B];
		states[B] = states[A];
		states[A] = tmp1 + tmp2;
		i++;
	}
}

INLINE static void	sha512_main_loop(uint64_t *states, uint64_t *clear
									 , uint64_t *last_blocks, uint64_t len)
{
	uint64_t		i;
	uint64_t		nbr_blocks;
	uint64_t		block_states[8];
	static uint64_t	message_schedule_array[80];
	uint64_t		extra_rounds;

	i = 0;
	nbr_blocks = len / 128;
	while (i < nbr_blocks)
	{
		ft_memcpy(block_states, states, sizeof(block_states));
		init_message_schedule_array(message_schedule_array, clear + i * 16);
		sha512_round(block_states, message_schedule_array);
		states[A] += block_states[A];
		states[B] += block_states[B];
		states[C] += block_states[C];
		states[D] += block_states[D];
		states[E] += block_states[E];
		states[F] += block_states[F];
		states[G] += block_states[G];
		states[H] += block_states[H];
		i++;
	}
	i = 0;
	extra_rounds = 1 + !!((len % 128) > (128 - 17));
	while (i < extra_rounds) {
		ft_memcpy(block_states, states, sizeof(block_states));
		init_message_schedule_array(message_schedule_array, last_blocks + i * 16);
		sha512_round(block_states, message_schedule_array);
		states[A] += block_states[A];
		states[B] += block_states[B];
		states[C] += block_states[C];
		states[D] += block_states[D];
		states[E] += block_states[E];
		states[F] += block_states[F];
		states[G] += block_states[G];
		states[H] += block_states[H];
		i++;
	}
}

uint64_t	 *sha512_hash(void *clear, uint64_t len)
{
	uint64_t		states[8];
	static uint8_t	last_blocks[256];
	uint64_t		*digest;
	uint32_t		i;

	if (clear == NULL)
		return (NULL);
	sha512_init(states);
	sha512_padding(clear, last_blocks, len);
	sha512_main_loop(states, clear, (uint64_t*)last_blocks, len);
	if (!(digest = malloc(sizeof(states))))
		return (NULL);
	if (ft_get_endianness())
	{
		i = 0;
		while (i < sizeof(states) / sizeof(*states))
		{
			states[i] = swap_int64(states[i]);
			i++;
		}
	}
	ft_memcpy(digest, states, sizeof(states));
	return (digest);
}
