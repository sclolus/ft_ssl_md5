/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   encode_des.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/26 21:31:33 by sclolus           #+#    #+#             */
/*   Updated: 2018/08/02 00:09:46 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"
#include "des.h"

const uint8_t	g_selection_tables[8][64] = {
	{
		14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
		0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
		4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
		15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
	},
	{
		15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
		3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
		0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
		13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
	},
	{
		10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
		13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
		13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
		1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
	},
	{
		7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
		13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
		10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
		3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
	},
	{
		2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
		14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
		4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
		11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
	},
	{
		12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
		10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
		9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
		4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
	},
	{
		4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
		13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
		1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
		6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
	},
	{
		13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
		1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
		7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
		2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
	},
};

const uint32_t	g_cipher_permutation_table[32] = {
	16, 7, 20, 21,
	29, 12, 28, 17,
	1, 15, 23, 26,
	5, 18, 31, 10,
	2, 8, 24, 14,
	32, 27, 3, 9,
	19, 13, 30, 6,
	22, 11, 4, 25,
};

const uint32_t	g_initial_permutation_table[64] = {
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7,
};

const uint32_t	g_inverse_permutation_table[64] = {
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41, 9, 49, 17, 57, 25,
};

const uint32_t	g_expansion_table[48] = {
	32, 1, 2, 3, 4, 5,
	4, 5, 6, 7, 8, 9,
	8, 9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32, 1,
};

const uint32_t	g_pc_1[56] = {
	57, 49, 41, 33, 25, 17, 9,
	1, 58, 50, 42, 34, 26, 18,
	10, 2, 59, 51, 43, 35, 27,
	19, 11, 3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	7, 62, 54, 46, 38, 30, 22,
	14, 6, 61, 53, 45, 37, 29,
	21, 13, 5, 28, 20, 12, 4,
};

const uint32_t	g_pc_2[48] = {
	14, 17, 11, 24, 1, 5,
	3, 28, 15, 6, 21, 10,
	23, 19, 12, 4, 26, 8,
	16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32,
};

const uint32_t	g_left_shift_schedule[16] = {
	1,
	1,
	2,
	2,
	2,
	2,
	2,
	2,
	1,
	2,
	2,
	2,
	2,
	2,
	2,
	1,
};

/// The permuted choice 1 function
/// returns a 56-bits value, the 8 most significant bits of the 64-bits encoded value should be ignored
static uint64_t	permuted_choice_1(uint8_t *key)
{
	uint64_t	pc;

	*(uint64_t*)(void*)bit_permutation(key, 56, g_pc_1, (uint8_t*)&pc) >>= 8;
	return (pc);
}

/// The permuted choice 2 function
/// returns a 48-bits value, the 16 most significant bits of the 64-bits encoded value should be ignored
/// the input value is the concatenation of the C() and D() values, with is a 56-bits value.
static uint64_t	permuted_choice_2(uint64_t cd)
{
	uint64_t	pc;

	*(uint64_t*)(void*)bit_permutation((uint8_t*)&cd, 48, g_pc_2, (uint8_t*)&pc) >>= 16;
	return (pc);
}

/// The key schedule function returns a block K_n composed of bits from the KEY
/// It takes as inputs the `key` and its subscript `n`
static uint64_t	key_schedule(uint8_t *key, uint8_t n)
{
	(void)(key);
	(void)n;
	uint64_t	tmp_pc;
	uint8_t		i;
	uint32_t	c;
	uint32_t	d;

	tmp_pc = permuted_choice_1(key);
	c = (uint32_t)(tmp_pc >> 28);
	d = tmp_pc & 0x000000000fffffff;
	i = 0;
	while (i < n)
	{
		c = left_rotate_32(c, g_left_shift_schedule[i]);
		d = left_rotate_32(d, g_left_shift_schedule[i]);
		i++;
	}
	return (permuted_choice_2(((uint64_t)c << 28) | (uint64_t)d));
}


/// The permutation function used in the definition of the cipher function f of des
/// it takes a 32-bits input block and shuffles it bits
static uint32_t	cipher_permutation_function(uint32_t selected_bits)
{
	uint32_t	permuted_output;

	permuted_output = 0; //might not be needed
	bit_permutation((uint8_t*)&selected_bits, 32, g_cipher_permutation_table, (uint8_t*)&permuted_output);
	return (permuted_output);
}

/// The selections function(s) for the cipher function f
/// it takes as input a 6-bit block, the 2 most significant bits of this argument is ignored by the selection function
/// the argument `n` refers to which selection function use
/// it returns the selected value in the selection_tables

static uint8_t	selection_function(uint8_t block, uint8_t n)
{
	uint8_t	row_index;
	uint8_t	column_index;

	row_index = ((block & 0x20) >> 0x4) | (block & 0x1);
	column_index = (block & 0x1e) >> 0x1;
	return (g_selection_tables[n][row_index * 16 + column_index]);
}

/// The expansion function for the cipher function f
/// actually a trick on the implementation of bit_permutation that won't overflow
/// if the indexies in the table are all inferior to the size of the input data

static uint64_t	expansion_function(uint32_t block)
{
	uint64_t expanded_block;

	expanded_block = 0; // might not be needed
	bit_permutation((uint8_t*)&block, 48, g_expansion_table, (uint8_t*)&expanded_block);
	return (expanded_block);
}

/// Returns a static permuted input block for the cipher function of des
static uint64_t	apply_initial_permutation(uint64_t input)
{
	uint64_t	permuted_input;

	permuted_input = 0; // migth not be needed
	bit_permutation((uint8_t*)&input, 64, g_initial_permutation_table, (uint8_t*)&permuted_input);
	return (permuted_input);
}

/// Returns a static permuted output block for the finalization of the des algorithm.
/// This is the inverse operation of the initial permutation IP.
/// As such, IP^-1(IP(input_block)) == input_block holds.

static uint64_t	apply_inverse_permutation(uint64_t preoutput)
{
	uint64_t	output;

	output = 0;
	bit_permutation((uint8_t*)&preoutput, 64, g_inverse_permutation_table, (uint8_t*)&output);
	return (output);
}


static void		test_selection_function(void)
{
	uint32_t	i;
	uint8_t		row_index;
	uint8_t		column_index;

	i = 0;
	while (i < 8)
	{
		row_index = 0;
		while (row_index < 4)
		{
			column_index = 0;
			while (column_index < 16)
			{
				uint8_t input = (uint8_t)((row_index & 0x2) << 4) | (uint8_t)(row_index & 0x1) | (uint8_t)(column_index << 0x1);
				uint8_t output = selection_function(input, (uint8_t)i);
				uint8_t expected = g_selection_tables[i][row_index * 16 + column_index];
				/* printf("n: %u, row_index: %hhu, column_index: %hhu\n", i, row_index, column_index); */
				/* printf("output: %hhu, expected: %hhu\n", output, expected); */
				assert( output == expected );
				column_index++;
			}
			row_index++;
		}
		i++;
	}
}

static uint32_t	cipher_des(uint32_t r, uint64_t k_n)
{
	uint64_t	blocks;
	uint32_t	selected_bits;
	uint8_t		i;

	i = 0;
	blocks = k_n ^ expansion_function(r);
	selected_bits = 0;
	while (i < 8)
	{
		selected_bits |= (uint32_t)(selection_function((uint8_t)((blocks >> ((7 - i) * 6)) & 0x3f), i) << (uint32_t)(26U - i * 6U)); //migth be 26
		i++;
	}
	return (cipher_permutation_function(selected_bits));
}

static uint64_t	des_encrypt_block(t_des_ctx *ctx)
{
	uint32_t	i;
	uint32_t	r;
	uint32_t	l;
	uint32_t	ciphered_32bits;
	uint64_t	preoutput;
	uint64_t	permuted_input;

	i = 0;
	permuted_input = apply_initial_permutation(*(uint64_t*)(void*)(ctx->data + ctx->total_len));
	permuted_input = swap_int64(permuted_input);
	l = (permuted_input) >> 32;
	r = (permuted_input) & 0x00000000ffffffff;
	while (i < 16)
	{
		ciphered_32bits = l ^ cipher_des(r, key_schedule(ctx->key, (uint8_t)i));
		l = r;
		r = ciphered_32bits;
		/* printf("---------L STATE: %u\n", i); */
		/* print_memory(&l, 4); */
		/* printf("---------R STATE: %u\n", i); */
		/* print_memory(&r, 4); */
		/* printf("\n"); */
		i++;
	}
	ctx->total_len += 8;
	preoutput = ((uint64_t)r) << 32 | (uint64_t)l;
	return (swap_int64(apply_inverse_permutation(preoutput)));
}

uint8_t	*encode_des(uint8_t *clear, uint64_t len, t_se_key *key)
{
	uint8_t		*cipher;
	t_des_ctx	ctx;

	cipher = NULL;
	(void)clear;
	(void)len;
	(void)key;
	(void)cipher_des;
	(void)key_schedule;
	ctx.data = clear;
	ctx.total_len = 0;
	ctx.key = key;
	assert(clear != NULL && key != NULL);
	/* print_memory(clear, 8); */
	/* printf("------PERMUTATION----------\n"); */
	/* uint64_t	permuted_input = (uint64_t)apply_initial_permutation(*(uint64_t*)(void*)ctx.data); */
	/* print_memory(&permuted_input, 8); */
	/* printf("------INVERSE PERMUTATION\n"); */
	/* memcpy(ctx.data, &permuted_input, 8); */
	/* permuted_input = (uint64_t)apply_inverse_permutation(*(uint64_t*)(void*)ctx.data); */
	/* print_memory(&permuted_input, 8); */
	/* memcpy(ctx.data, &permuted_input, 8); */
	/* printf("-------CURRENT MEMORY---------\n"); */
	/* print_memory(ctx.data, 4); */
	/* printf("-------EXPANSION---------\n"); */
	/* permuted_input = (uint64_t)expansion_function(*(uint32_t*)(void*)ctx.data); */
	/* print_memory(&permuted_input, 6); */
	/* assert(5 == selection_function(27, 0)); */
	/* memcpy(ctx.data, &permuted_input, 6); */
	/* printf("-------CIPHER_PERMUTATION--------\n"); */
	/* permuted_input = (uint64_t)cipher_permutation_function(*(uint32_t*)(void*)ctx.data); */
	/* print_memory(&permuted_input, 4); */

	printf("----------CLEARTEXT-----------\n");
	print_memory(ctx.data, 8);
	uint64_t cipher_block = des_encrypt_block(&ctx);
	printf("-----------CIHPER BLOCK-----------\n");
	print_memory(&cipher_block, 8);
	test_selection_function();
	if (1)
		exit(EXIT_SUCCESS);
	return (NULL);
}
