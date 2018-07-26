/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   read_message_from_stdin.c                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/25 01:52:53 by sclolus           #+#    #+#             */
/*   Updated: 2018/07/26 03:07:02 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

static int32_t		ft_get_file_content_string(t_string *string, int fd)
{
	static char	buffer[BUFF_SIZE];
	ssize_t		n;

	while ((n = read(fd, buffer, BUFF_SIZE)))
	{
		if (n == -1)
			return (-1);
		ft_t_string_concat_len(string, buffer, (uint32_t)n);
	}
	return (0);
}

t_string	read_message_from_stdin(void)
{
	t_string	string;

	if (!(string.string = (char*)malloc(sizeof(char) * 256)))
		ft_error_exit(1, (char*[]){ERR_GET_FILE_CONTENT_MALLOC}, EXIT_FAILURE);
	string.capacity = 256;
	string.len = 0;
	string.string[0] = '\0';
	if (-1 == (ft_get_file_content_string(&string, STDIN_FILENO)))
	{
		free(string.string);
		return ((t_string){0, 0, NULL});
	}
	return (string);
}
