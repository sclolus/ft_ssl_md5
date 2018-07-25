/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sha256.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/19 05:11:08 by sclolus           #+#    #+#             */
/*   Updated: 2018/07/25 02:44:08 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

static const uint32_t	g_sha256_constants[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
	0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
	0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
	0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
	0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
	0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
	0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
	0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
	0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

INLINE static void		sha256_init(uint32_t *states)
{
	states[A] = 0x6a09e667;
	states[B] = 0xbb67ae85;
	states[C] = 0x3c6ef372;
	states[D] = 0xa54ff53a;
	states[E] = 0x510e527f;
	states[F] = 0x9b05688c;
	states[G] = 0x1f83d9ab;
	states[H] = 0x5be0cd19;
}

INLINE static void		sha256_padding(uint8_t *clear, uint8_t *last_blocks
									   , uint64_t len)
{
	uint64_t	printed_len;

	ft_bzero(last_blocks, 128);
	ft_memcpy(last_blocks, clear + len - len % 64, len % 64);
	*((uint8_t*)last_blocks + len % 64) |= 0x80;
	printed_len = len * 8;
	if (ft_get_endianness())
		printed_len = swap_int64(printed_len);
	((uint64_t*)(void*)last_blocks)[7 + 8 * ((len % 64) > 64 - 9)] = printed_len;
	assert(!memcmp(last_blocks, clear + len - len % 64, len % 64));
}


INLINE static void	init_message_schedule_array(uint32_t *array, uint32_t *block)
{
	uint64_t	i;
	uint32_t	j = 0;
	uint32_t	tmp_1;
	uint32_t	tmp_2;

	ft_bzero(array, 64 * sizeof(uint32_t)); //should be removed
	if (ft_get_endianness())
		while (j < 16)
		{
			array[j] = swap_int32(block[j]);
			j++;
		}
	i = 16;
	while (i < 64)
	{
		tmp_1 = right_rotate_32(array[i - 15], 7)
			^ right_rotate_32(array[i - 15], 18)
			^ (array[i - 15] >> 3);
		tmp_2 = right_rotate_32(array[i - 2], 17)
			^ right_rotate_32(array[i - 2], 19)
			^ (array[i - 2] >> 10);
		array[i] = array[i - 16] + tmp_1 + array[i - 7] + tmp_2;
		i++;
	}
}

INLINE static void	sha256_round(uint32_t *states, uint32_t *message_schedule_array)
{
	uint64_t	i;
	uint32_t	s1;
	uint32_t	s0;
	uint32_t	ch;
	uint32_t	tmp1;
	uint32_t	maj;
	uint32_t	tmp2;

	i = 0;
	while (i < 64)
	{
		s1 = (right_rotate_32(states[E], 6)) ^ (right_rotate_32(states[E], 11))
			^ (right_rotate_32(states[E], 25));
		ch = (states[E] & states[F]) ^ (~(states[E]) & states[G]);
		tmp1 = states[H] + s1 + ch + g_sha256_constants[i] + message_schedule_array[i];
		s0 = (right_rotate_32(states[A], 2))
			^ (right_rotate_32(states[A], 13))
			^ (right_rotate_32(states[A], 22));
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

INLINE static void	sha256_main_loop(uint32_t *states, uint32_t *clear
									 , uint32_t *last_blocks, uint64_t len)
{
	uint64_t		i;
	uint64_t		nbr_blocks;
	uint32_t		block_states[8];
	static uint32_t	message_schedule_array[64];
	uint64_t		extra_rounds;

	i = 0;
	nbr_blocks = len / 64;
	while (i < nbr_blocks)
	{
		ft_memcpy(block_states, states, sizeof(block_states));
		init_message_schedule_array(message_schedule_array, clear + i * 16);
		sha256_round(block_states, message_schedule_array);
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
	extra_rounds = 1 + !!((len % 64) > (64 - 9));
	while (i < extra_rounds) {
		ft_memcpy(block_states, states, sizeof(block_states));
		init_message_schedule_array(message_schedule_array, last_blocks + i * 16);
		sha256_round(block_states, message_schedule_array);
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

uint32_t	 *sha256_hash(void *clear, uint64_t len)
{
	uint32_t		states[8];
	static uint8_t	last_blocks[128];
	uint32_t		*digest;
	uint32_t		i;

	if (clear == NULL)
		return (NULL);
	sha256_init(states);
	sha256_padding(clear, last_blocks, len);
	sha256_main_loop(states, clear, (uint32_t*)last_blocks, len);
	if (!(digest = malloc(sizeof(states))))
		return (NULL);
	if (ft_get_endianness())
	{
		i = 0;
		while (i < 8)
		{
			states[i] = swap_int32(states[i]);
			i++;
		}
	}
	ft_memcpy(digest, states, sizeof(states));
	return (digest);
}
