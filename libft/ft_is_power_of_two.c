/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_is_power_of_two.c                               :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2016/12/09 04:30:16 by sclolus           #+#    #+#             */
/*   Updated: 2018/08/02 07:06:47 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdio.h>
unsigned int	ft_is_power_of_two(unsigned long long nbr)
{
	printf("je recois cela: %llx\n", nbr);
	return ((nbr & (nbr - 1)) == 0);
}
