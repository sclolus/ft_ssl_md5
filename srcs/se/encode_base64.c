/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   encode_base64.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/26 01:40:15 by sclolus           #+#    #+#             */
/*   Updated: 2018/07/26 18:49:55 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

static INLINE uint32_t	update_24bits(uint8_t byte1, uint8_t byte2, uint8_t byte3)
{
	return ((uint32_t)(byte1 << 16) | (uint32_t)(byte2 << 8) | (uint32_t)byte3);
}

static INLINE void		encode_24bits(uint8_t *cipher, uint32_t tmp)
{
	cipher[0] = (uint8_t)(BASE64_CHARS[(tmp & 0x00fc0000) >> 18]);
	cipher[1] = (uint8_t)(BASE64_CHARS[(tmp & 0x0003f000) >> 12]);
	cipher[2] = (uint8_t)(BASE64_CHARS[(tmp & 0x00000fc0) >> 6]);
	cipher[3] = (uint8_t)(BASE64_CHARS[(tmp & 0x0000003f)]);
}

uint8_t		*encode_base64(uint8_t *clear, uint64_t len, t_se_key *key)
{
	uint64_t	i;
	uint64_t	cipher_index;
	uint8_t		*cipher;
	uint32_t	tmp;

	i = 0;
	cipher_index = 0;
	if (!(cipher = (uint8_t *)malloc((len * 8) / 24 * 4 + !!(len % 3) * 4 + 1)))
		ft_error_exit(1, (char*[]){MALLOC_FAILURE}, EXIT_FAILURE);
	cipher[(len * 8) / 24 * 4 + (!!(len % 3)) * 4] = '\0';
	while (i + 2 < len)
	{
		tmp = update_24bits(clear[i], clear[i + 1], clear[i + 2]);
		encode_24bits(cipher + cipher_index, tmp);
		i += 3;
		cipher_index += 4;
	}
	if (len % 3)
	{
		tmp = update_24bits(clear[i], len % 3 == 2 ? clear[i + 1] : 0, 0);
		encode_24bits(cipher + cipher_index, tmp);
		cipher[cipher_index + 2] = (len % 3 == 1)
			? '='
			: cipher[cipher_index + 2];
		cipher[cipher_index + 3] = '=';
	}
	(void)key;
	return (cipher);
}
