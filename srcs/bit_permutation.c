/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   bit_permutation.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/08/01 06:23:31 by sclolus           #+#    #+#             */
/*   Updated: 2018/08/02 08:41:53 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

uint8_t	*bit_permutation(const uint8_t *data
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
