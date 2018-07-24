/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   print_hash.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/24 22:45:23 by sclolus           #+#    #+#             */
/*   Updated: 2018/07/25 01:31:52 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

void	print_hash(uint32_t *digest, uint64_t size, int32_t swap_endian)
{
	uint32_t	i;
	uint32_t	tmp;

	i = 0;
	while (i < size / 4)
	{
		tmp = digest[i];
		if (swap_endian)
			tmp = swap_int32(tmp);
		printf("%8.8x", tmp);
		i++;
	}
}
