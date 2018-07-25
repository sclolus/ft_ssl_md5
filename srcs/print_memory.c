/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   print_memory.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: exam <marvin@42.fr>                        +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/11/22 10:02:01 by exam              #+#    #+#             */
/*   Updated: 2018/07/25 22:24:22 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

static void	ft_putnbr_base(int nbr, char *base)
{
	if (nbr > 15)
	{
		ft_putnbr_base(nbr / 16, base);
		ft_putnbr_base(nbr % 16, base);
	}
	else
		ft_putchar((unsigned char)base[nbr]);
}

static void	ft_put_blanks(size_t size)
{
	size_t	i;

	i = 0;
	while (i < size)
	{
		if (!(i % 2))
			ft_putchar(' ');
		ft_putchar(' ');
		ft_putchar(' ');
		i++;
	}
}

static void	ft_print_memory(const void *addr, size_t size)
{
	const unsigned char	*tmp;
	size_t				i;

	tmp = (const unsigned char *)addr;
	i = 0;
	while (i < size)
	{
		if (tmp[i] < 16)
			ft_putchar('0');
		ft_putnbr_base(tmp[i++], "0123456789abcdef");
		if (!(i % 2))
			ft_putchar(' ');
	}
	if (size < 16)
		ft_put_blanks(16 - size);
	i = 0;
	while (i < size)
	{
		if (tmp[i] < 32 || tmp[i] >= 127)
			ft_putchar('.');
		else
			ft_putchar((unsigned char)tmp[i]);
		i++;
	}
}

void		print_memory(const void *addr, size_t size)
{
	if (!addr)
		return ;
	while (size / 16)
	{
		ft_print_memory((const void*)addr, 16);
		size -= 16;
		addr = (const void*)((const unsigned char*)addr + 16);
		ft_putchar('\n');
	}
	if (size % 16)
	{
		ft_print_memory((const void*)addr, size);
		ft_putchar('\n');
	}
}
