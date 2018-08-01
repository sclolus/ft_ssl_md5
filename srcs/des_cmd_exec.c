/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   des_cmd_exec.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/26 21:39:05 by sclolus           #+#    #+#             */
/*   Updated: 2018/08/01 05:23:19 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"
#include "des.h"

void	des_cmd_exec(t_command_line *cmd)
{
	t_string	message;
	int			output_fd;
	uint8_t		*cipher;

	if (cmd->info.se.flags.des.i && cmd->info.se.input_file)
		message = read_input_file(cmd->info.se.input_file);
	else
		message = read_message_from_stdin();
	if (cmd->info.se.flags.des.o && cmd->info.se.output_file)
	{
		if (-1 == (output_fd = open(cmd->info.se.output_file, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR)))
			ft_error_exit(2, (char*[]){ERR_FILE_OPEN, cmd->info.se.output_file}, EXIT_FAILURE);
	}
	else
		output_fd = STDOUT_FILENO;
	if (cmd->info.se.key == NULL && cmd->info.se.password == NULL)
		ft_error_exit(1, (char*[]){DES_NO_KEY_OR_PASSWORD}, EXIT_FAILURE);
	if (cmd->info.se.flags.des.e)
		cipher = encode_des((uint8_t *)message.string, message.len, (uint8_t *)cmd->info.se.key);
	else
	{
		printf("cipher: %s\n", message.string);
		cipher = decode_des((uint8_t *)message.string, message.len, (uint8_t *)cmd->info.se.key);
	} // THE WHITESPACE FOR GOD'S SAKE
	write(output_fd, cipher, ft_strlen((const char*)cipher));

	(void)cmd;
}
