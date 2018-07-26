/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   read_input_file.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/26 03:01:24 by sclolus           #+#    #+#             */
/*   Updated: 2018/07/26 03:01:44 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

INLINE t_string	read_input_file(char *filename)
{
	t_string	message;

	message = ft_get_file_content(filename);
	if (message.string == NULL)
		ft_error_exit(2, (char*[]){ERR_FILE_OPEN
					, filename}, 0); //check this
	return (message);
}
