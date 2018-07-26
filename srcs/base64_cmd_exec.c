/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   base64_cmd_exec.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/26 01:53:23 by sclolus           #+#    #+#             */
/*   Updated: 2018/07/26 05:34:12 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

void			base64_cmd_exec(t_command_line *cmd)
{
	t_string	message;
	int			output_fd;
	uint8_t		*cipher;

	if (cmd->info.se.flags.base64.i && cmd->info.se.input_file)
		message = read_input_file(cmd->info.se.input_file);
	else
		message = read_message_from_stdin();
	if (cmd->info.se.flags.base64.o && cmd->info.se.output_file)
	{
		if (-1 == (output_fd = open(cmd->info.se.output_file, O_WRONLY | O_CREAT | O_TRUNC)))
			ft_error_exit(2, (char*[]){ERR_FILE_OPEN, cmd->info.se.output_file}, EXIT_FAILURE);
	}
	else
		output_fd = STDOUT_FILENO;
	if (cmd->info.se.flags.base64.e)
		cipher = encode_base64((uint8_t *)message.string, message.len, NULL);
	else
	{
		printf("cipher: %s\n", message.string);
		cipher = decode_base64((uint8_t *)message.string, message.len, NULL);
	}
	write(output_fd, cipher, ft_strlen((const char*)cipher));
	write(output_fd, "\n", 1);
//	write(output_fd, cipher, message.len);
	/* printf("\ninput file: %s\noutput_file: %s\n", cmd->info.se.input_file, cmd->info.se.output_file); */
	/* printf("d: %hhu\n", cmd->info.se.flags.base64.d); */
	/* printf("e: %hhu\n", cmd->info.se.flags.base64.e); */
	/* printf("i: %hhu\n", cmd->info.se.flags.base64.i); */
	/* printf("o: %hhu\n", cmd->info.se.flags.base64.o); */
}
