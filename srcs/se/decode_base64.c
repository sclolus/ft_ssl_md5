/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   decode_base64.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/26 05:20:46 by sclolus           #+#    #+#             */
/*   Updated: 2018/07/26 19:32:05 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

// this should be replace with the inverse hash table of the BASE64 char-set
static INLINE uint32_t	decode_32bits(uint8_t byte0, uint8_t byte1
									   , uint8_t byte2, uint8_t byte3)
{
	byte0 *= !(byte0 == '=');
	byte1 *= !(byte1 == '=');
	byte2 *= !(byte2 == '=');
	byte3 *= !(byte3 == '=');
	return (((uint32_t)(ft_strchr(BASE64_CHARS, byte0) - BASE64_CHARS) << 18)
			| ((uint32_t)(ft_strchr(BASE64_CHARS, byte1) - BASE64_CHARS) << 12)
			| ((uint32_t)(ft_strchr(BASE64_CHARS, byte2) - BASE64_CHARS) << 6)
			| (uint32_t)(ft_strchr(BASE64_CHARS, byte3) - BASE64_CHARS));
}

uint8_t					*decode_base64(uint8_t *cipher, uint64_t len, t_se_key *key)
{
	uint8_t		*clear;
	uint64_t	i;
	uint64_t	clear_index;

	i = 0;
	clear_index = 0;
	if (!(clear = (uint8_t *)malloc(len + 1)))
		ft_error_exit(1, (char*[]){MALLOC_FAILURE}, EXIT_FAILURE);
	ft_bzero(clear, len);
	while (i + 3 < len)
	{
		*((uint32_t*)(void*)(clear + clear_index)) |= ft_get_endianness()
			? swap_int32(decode_32bits(cipher[i], cipher[i + 1], cipher[i + 2], cipher[i + 3]) << 8)
			: (decode_32bits(cipher[i], cipher[i + 1], cipher[i + 2], cipher[i + 3]) << 8); //remove ft_get_endianness
		clear_index += 3;
		i += 4;
	}
	i = len - 4;
	while (i < len)
	{
		if (cipher[i] == '=')
			clear[clear_index - (len - i)] = '\0';
		i++;
	}
	clear[clear_index] = '\0';
	(void)key;
	return (clear);
}
