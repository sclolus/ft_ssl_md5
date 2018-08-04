/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   str_to_key.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/08/04 11:03:44 by sclolus           #+#    #+#             */
/*   Updated: 2018/08/04 11:19:27 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

inline static uint8_t	atoi_x(char c)
{
	const uint8_t	hex_tab[16][2] = { // not capital ?
		{'0', 0x0},
		{'1', 0x1},
		{'2', 0x2},
		{'3', 0x3},
		{'4', 0x4},
		{'5', 0x5},
		{'6', 0x6},
		{'7', 0x7},
		{'8', 0x8},
		{'9', 0x9},
		{'A', 0xA},
		{'B', 0xB},
		{'C', 0xC},
		{'D', 0xD},
		{'E', 0xE},
		{'F', 0xF},
	};
	uint32_t	i;

	i = 0;
	while (i < sizeof(hex_tab) / sizeof(*hex_tab))
	{
		if (hex_tab[i][0] == c)
			return (hex_tab[i][1]);
		i++;
	}
	ft_error_exit(1, (char*[]){"Invalid character found in key"}, EXIT_FAILURE);
}

uint8_t			*str_to_key(char *str)
{
	uint8_t		*key;
	uint64_t	key_size;
	uint64_t	len;
	uint64_t	i;

	len = ft_strlen(str);
	key_size = len / 2 + !!(len % 2);
	if (!(key = (uint8_t*)malloc(sizeof(uint8_t) * key_size)))
		return (NULL);
	ft_bzero(key, key_size);
	i = 0;
	while (i < len)
	{
		key[i / 2] = (uint8_t)(atoi_x(str[i]) << 4U);
		key[i / 2] = atoi_x(str[i + 1]);
		i += 2;
	}
	return (key);
}
