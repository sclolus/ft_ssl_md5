/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   bit_permutation.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/08/01 06:23:31 by sclolus           #+#    #+#             */
/*   Updated: 2018/08/04 03:34:05 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

inline uint8_t	*bit_permutation(const uint8_t *data
						 , uint32_t size
						 , const uint32_t *permutation_table
						 , uint8_t *output)
{
	uint32_t		i;
	uint8_t			permutation_index;

	i = 0;
	while (i < size)
	{
		permutation_index = (uint8_t)(permutation_table[i] - 1U);
		output[(size / 8U - 1U) - i / 8U] |= (uint8_t)((((data[(size / 8U - 1U) - permutation_index / 8U])
									>> (7U - permutation_index % 8U)) & 0x1U) << (7U - i % 8U));
		i++;
	}
	printf("\n");
	return (output);
}

inline uint64_t	bits64_permutation(uint64_t source, uint32_t size, const uint32_t *permutation_table)
{
	uint32_t	i;
	uint64_t	result;

	i = 0U;
	result = 0U;
	assert(size <= 64 && size);
	while (i < size)
	{
		if (source & (0x1UL << (size - (permutation_table[i]))))
			result |= (uint64_t)(0x1UL << ((uint32_t)size - 1UL - i));
		i++;
	}
	return (result);
}

inline uint32_t	bits32_permutation(uint32_t source, uint32_t size, const uint32_t *permutation_table)
{
	uint32_t	i;
	uint32_t	result;

	i = 0U;
	result = 0U;
	assert(size <= 32);
	while (i < size)
	{
		if (source & (0x1U << (size - (permutation_table[i]))))
			result |= (uint32_t)(0x1U << ((uint32_t)size - 1 - i));
		i++;
	}
	return (result);
}
