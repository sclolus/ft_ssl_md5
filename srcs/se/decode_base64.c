/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   decode_base64.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/26 05:20:46 by sclolus           #+#    #+#             */
/*   Updated: 2018/07/26 05:41:47 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

uint8_t	*decode_base64(uint8_t *cipher, uint64_t len, t_se_key *key)
{
	uint8_t		*clear;
	uint32_t	clear_tmp;
	uint64_t	i;
	uint64_t	clear_index;

	i = 0;
	clear_index = 0;
	if (!(clear = (uint8_t *)malloc(len + 1)))
		ft_error_exit(1, (char*[]){MALLOC_FAILURE}, EXIT_FAILURE);
	ft_bzero(clear, len);
	while (i + 3 < len)
	{
		clear_tmp = ((uint32_t)(ft_strchr(BASE64_CHARS, cipher[i]) - BASE64_CHARS) << 18)
			| ((uint32_t)(ft_strchr(BASE64_CHARS, cipher[i + 1]) - BASE64_CHARS) << 12)
			| ((uint32_t)(ft_strchr(BASE64_CHARS, cipher[i + 2]) - BASE64_CHARS) << 6)
			| (uint32_t)(ft_strchr(BASE64_CHARS, cipher[i + 3]) - BASE64_CHARS);
		*((uint32_t*)(void*)(clear + clear_index)) |= swap_int32(clear_tmp << 8);
		clear_index += 3;
		i += 4;
	}
	clear[clear_index] = '\0';
	print_memory(clear, clear_index);
	(void)key;
	return (clear);
}
