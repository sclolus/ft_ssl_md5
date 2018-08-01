/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   bit_permutation.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/08/01 06:23:31 by sclolus           #+#    #+#             */
/*   Updated: 2018/08/01 06:25:13 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

uint8_t	*bit_permutation(uint8_t *data
						 , uint32_t size
						 , const uint32_t *permutation_table
						 , uint8_t *output)
{
	uint32_t		i;
	uint32_t		permutation_index;

	i = 0;
	while (i < size)
	{
		permutation_index = permutation_table[i] - 1;
		output[i / 8] |= (((data[permutation_index / 8]) >> (7 - permutation_index % 8)) & 0x1) << (7 - i % 8);
		i++;
	}
	return (output);
}
