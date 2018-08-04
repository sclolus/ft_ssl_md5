/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   encode_des.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/26 21:31:33 by sclolus           #+#    #+#             */
/*   Updated: 2018/08/04 11:41:34 by sclolus          ###   ########.fr       */
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
static uint64_t	permuted_choice_1(uint64_t key)
{
	uint64_t	pc;
	uint64_t	be_key;

	be_key = (key);
	pc = bits64_permutation(be_key, 56, g_pc_1);
 	return (pc);
}

static void		test_permuted_choice_1(void)
{
	const uint64_t key = (0x0606060606060606);
	const uint64_t expected_result = 0x0000000ffff000;
	uint64_t		result;

	result = permuted_choice_1(key);
	if (expected_result != result) {
		printf("$$$$$$$test_permuted_choice_1$$$$$$\n");
		printf("----expected_result----\n");
		print_memory(&expected_result, 8);
		printf("----result----\n");
		print_memory(&result, 8);
		printf("----trusted_result----\n");
	}
	assert(expected_result == result);
}

# define HIBIT_64 0x8UL << 60UL
INLINE static void		print_bin_64(uint64_t	nbr)
{
	uint32_t	i;
	uint32_t	pad;

	i = 0;
	printf("1      8       16       24       32       40       48       56       64\n");
	pad = 0;
	while (i < 64)
	{
		if ((HIBIT_64 >> i) & nbr)
			break;
		pad++;
		i++;
	}
	uint32_t tmp_pad = pad;
	while (pad)
	{
		printf("0");
		pad--;
		if (!((tmp_pad - pad) % 8))
			printf(" ");
	}
	while (i < 64)
	{
		if ((HIBIT_64 >> i) & nbr)
			printf("1");
		else
			printf("0");

		i++;
		if (!((i) % 8))
			printf(" ");
	}
	printf("\n");
}

INLINE static uint64_t	set_bit(uint64_t source, uint32_t to, uint32_t from, uint64_t target)
{
	target &= ~(0x1UL << (64U - to));
	target |= ((source >> (64U - from)) & 0x1UL) << (64U - to);
	return (target);
}

/// The permuted choice 2 function
/// returns a 48-bits value, the 16 most significant bits of the 64-bits encoded value should be ignored
/// the input value is the concatenation of the C() and D() values, with is a 56-bits value.
static uint64_t	permuted_choice_2(uint64_t cd)
{
	uint64_t	pc;
	uint32_t	i;

	pc = cd;
	i = 0;
	uint8_t tmp;
	(void)print_bin_64;
	while (i < 48)
	{
		/* printf("---------------cd--------------\n"); */
		/* print_bin_64(cd); */
		/* printf("---------------end--------------\n"); */
		/* printf("setting the bit %u to the bit position %u on pc\n", g_pc_2[i] + 8, i + 1); */
		pc = set_bit(cd, i + 1 + 16, g_pc_2[i], pc);
//		print_bin_64(pc);
		i++;
//		read(0, &tmp, 1);
	}
	//	print_bin_64(pc);
	tmp = 0;
	/* printf("pc: %013llx\n", pc); */
	/* if (pc) */
	/* 	exit(1); */
	return (pc);
}

static inline uint32_t	left_rotate_28(uint32_t word, uint32_t delta)
{
	assert(delta <= 27);
	return (
		((word << delta) & (0x0fffffff))
		| (word >> ((28 - delta)))
			);
}

/// The key schedule function returns a block K_n composed of bits from the KEY
/// It takes as inputs the `key` and its subscript `n`
static uint64_t	key_schedule(uint64_t key, uint8_t n)
{
	uint32_t	i;
	uint32_t	c;
	uint32_t	d;

	key = permuted_choice_1(key);
	c = (uint32_t)(key >> 28UL);
	d = (uint32_t)(key & 0xfffffff);
	d = 0xffff;
	printf("pre_shifts c: %07x, d: %07x\n", c, d);
	i = 0;
	while (i < n)
	{
		c = left_rotate_28(c, g_left_shift_schedule[i]);
		d = left_rotate_28(d, g_left_shift_schedule[i]);
		i++;
	}
	printf("pre_permutation i: %u c: %07x, d: %07x\n", i, c, d);
	//	printf("pre_permutation i: %u cd: %016llx\n", i, ((uint64_t)c << 28) | ((uint64_t)d & 0xfffffff));
/* 	printf("i: %u c: %08x, d: %08x\n", i, c, d); */
/* 	printf("c: \n"); */
/* 	print_bin_64((uint64_t)c); */
/* 	printf("d: \n"); */
/* 	print_bin_64((uint64_t)d); */
/* 	printf("input to pc2:\n"); */
//	uint64_t pc2_input = ((uint64_t)c << 28UL) | ((uint64_t)d);
	//	print_bin_64(pc2_input);
	//	uint64_t pc2_output = permuted_choice_2(pc2_input);
	//	printf("my_permutation i: %u cd: %012llx\n", i, pc2_output);
	return (permuted_choice_2(((uint64_t)c << 28) | ((uint64_t)d & 0xfffffff)));
}

static void	get_des_subkeys(t_des_ctx *ctx)
{
	uint32_t	i;

	i = 1;
//	print_memory(ctx->key, 8);
	const uint64_t key = 0x0606060606060606;
	while (i <= 16)
	{
		ctx->subkeys[i - 1] = key_schedule(/* *(uint64_t*)(void*)ctx->key */key, (uint8_t)i);
		//	printf("\nsubkey: %02u, key: %016llx\n", i, ctx->subkeys[i - 1]);
		i++;
	}
	/* if (i) */
	/* 	exit(EXIT_SUCCESS); */
}

/// The permutation function used in the definition of the cipher function f of des
/// it takes a 32-bits input block and shuffles it bits
static uint32_t	cipher_permutation_function(uint32_t selected_bits)
{
	uint32_t	permuted_output;

	permuted_output = bits32_permutation(selected_bits, 32, g_cipher_permutation_table);
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

/// The expansion function for the cipher function f
/// actually a trick on the implementation of bit_permutation that won't overflow
/// if the indexies in the table are all inferior to the size of the input data

static uint64_t	expansion_function(uint32_t block)
{
	uint64_t expanded_block;

	expanded_block = bits64_permutation(block, 48, g_expansion_table);
	return (expanded_block);
}

/// Returns a static permuted input block for the cipher function of des
static uint64_t	apply_initial_permutation(uint64_t input)
{
	uint64_t	permuted_input;

	permuted_input = bits64_permutation(input, 64, g_initial_permutation_table);
	return (permuted_input);
}

/// Returns a static permuted output block for the finalization of the des algorithm.
/// This is the inverse operation of the initial permutation IP.
/// As such, IP^-1(IP(input_block)) == input_block holds.

static uint64_t	apply_inverse_permutation(uint64_t preoutput)
{
	uint64_t	output;

	output = bits64_permutation(preoutput, 64, g_inverse_permutation_table);
	return (output);
}

static uint32_t	cipher_des(uint32_t r, uint64_t k_n)
{
	uint64_t	blocks;
	uint32_t	selected_bits;
	uint32_t	selection_function_result;
	uint8_t		i;

	i = 0;
	blocks = k_n ^ expansion_function(r);
	selected_bits = 0;
	while (i < 8)
	{
		selection_function_result = selection_function((uint8_t)((blocks >> (42 - i * 6UL)) & 0x3f), i);
		selected_bits |= ((uint32_t)selection_function_result << (uint32_t)(28U - i * 4U)); //migth be 26
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
	permuted_input = apply_initial_permutation(ctx->data);
	l = (permuted_input) >> 32;
	r = (permuted_input) & 0x00000000ffffffff;
	while (i < 16)
	{
		ciphered_32bits = l ^ cipher_des(r, ctx->subkeys[i]);
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
	preoutput = ((uint64_t)r << 32UL) | ((uint64_t)l);
	return ((apply_inverse_permutation(preoutput)));
}

static void	test_bit_permutation(void)
{
	const uint32_t	test_table[64] = {
		64, 63, 62, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51,
		50, 49, 48, 47, 46, 45, 44, 43, 42, 41, 40, 39, 38, 37,
		36, 35, 34, 33, 32, 31, 30, 29, 28, 27, 26, 25, 24, 23,
		22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9,
		8, 7, 6, 5, 4, 3, 2, 1
	};

	const uint64_t input = 0x5555555555555500;
	uint64_t output = 0;
	const uint64_t expected_output = 0x00AAAAAAAAAAAAAA;

//	bit_permutation((const uint8_t*)(const void*)&input, 56, test_table, (uint8_t*)(void*)&output);
	output = bits64_permutation(input, 64, test_table);
	if (output != expected_output) {
		printf("$$$$$test_bit_permutation$$$$$$\n");
		printf("-------expected_output------\n");
		print_memory(&expected_output, 8);
		printf("-------output------\n");
		print_memory(&output, 8);
	}
	assert(output == expected_output);
}

static void		test_assert_inverse_permutation(void)
{
	uint32_t	i;
	uint32_t	result_inverse_table[64];

	i = 0;
	while (i < 64)
	{
		result_inverse_table[g_initial_permutation_table[i] - 1] = i + 1;
		i++;
	}
	i = 0;
	assert(!memcmp(result_inverse_table, g_inverse_permutation_table, sizeof(g_inverse_permutation_table)));
}

static void	test_bits32_permutation(void)
{
	uint32_t	table32[32];
	uint32_t	inverse_table32[32];
	uint32_t	i;

	i = 0;
	while (i < 32)
	{
		table32[i] = i + 1U;
		i++;
	}
	i = 0;
	while (i < 32)
	{

		inverse_table32[table32[i] - 1] = i + 1U;
		i++;
	}
	assert(bits32_permutation(bits32_permutation((uint32_t)0xfedabecc, 32, inverse_table32), 32, table32) == (uint32_t)0xfedabecc);
}

static void	test_bits64_permutation(void)
{
	assert(bits64_permutation(bits64_permutation(0xfedabeccabababab
				 , 64, g_initial_permutation_table), 64, g_inverse_permutation_table) == 0xfedabeccabababab);

	uint32_t	table48[48];
	uint32_t	inverse_table48[48];
	uint32_t	i = 0;

	i = 0;
	while (i < 48U)
	{
		table48[i] = (i * 2 + 1 * ((i / 24U))) % 48 + 1;
		i++;
	}
	i = 0;
	while (i < 48U)
	{
		inverse_table48[table48[i] - 1] = i + 1U;
		i++;
	}
	uint64_t	value;
	uint32_t	initial_value = 0xfedabecc;
	print_memory(&initial_value, 4);
	value = bits64_permutation((uint64_t)initial_value, 48, table48);
	print_memory(&value, 6);
	value = bits64_permutation(value, 48, inverse_table48);
	print_memory(&value, 6);
	assert(value == (uint64_t)initial_value);
}

uint8_t	*encode_des(uint8_t *clear, uint64_t len, t_se_key *key)
{
	t_des_ctx	ctx;


	(void)clear;
	(void)len;
	(void)key;
	assert(clear != NULL && key != NULL);
	ctx.data = *(uint64_t*)(void*)clear;
	ctx.total_len = 0;
	ctx.key = key;
	printf("key: %016llx\n", *(uint64_t*)(void*)ctx.key);
	if (!(ctx.cipher = (uint8_t*)malloc(len)))
		return (NULL);
	(void)get_des_subkeys;
	get_des_subkeys(&ctx);

	/* print_memory(clear, 8); */
	/* printf("------PERMUTATION----------\n"); */
	/* uint64_t	permuted_input = (uint64_t)apply_initial_permutation(ctx.data); */
	/* print_memory(&permuted_input, 8); */
	/* printf("------INVERSE PERMUTATION\n"); */
	/* memcpy(&ctx.data, &permuted_input, 8); */
	/* permuted_input = (uint64_t)apply_inverse_permutation(ctx.data); */
	/* print_memory(&permuted_input, 8); */

	uint64_t	tmp;

	tmp = bits64_permutation(ctx.data, 64, g_initial_permutation_table);
	tmp = bits64_permutation(tmp, 64, g_inverse_permutation_table);
	assert(tmp == ctx.data);
	test_bits32_permutation();
	test_bits64_permutation();
	test_permuted_choice_1();
	test_selection_function();
	test_bit_permutation();
	test_assert_inverse_permutation();
	assert(ctx.data == apply_inverse_permutation(apply_initial_permutation(ctx.data)));

//	uint64_t	expanded_value;
	/* printf("-------EXPANSION---------\n"); */
	/* print_memory(&ctx.data, 4); */
	/* expanded_value = expansion_function((uint32_t)ctx.data); */
	/* print_memory(&expanded_value, 6); */
	/* memcpy(ctx.data, &permuted_input, 6); */
	/* printf("-------CIPHER_PERMUTATION--------\n"); */
	/* permuted_input = (uint64_t)cipher_permutation_function(*(uint32_t*)(void*)ctx.data); */
	/* print_memory(&permuted_input, 4); */



	printf("----------CLEARTEXT-----------\n");
	print_memory(&ctx.data, 8);
	(void)des_encrypt_block;
	uint64_t cipher_block = des_encrypt_block(&ctx);
	printf("-----------CIHPER BLOCK-----------\n");
	print_memory(&cipher_block, 8);
	if (1)
		exit(EXIT_SUCCESS);
	return (NULL);
}
