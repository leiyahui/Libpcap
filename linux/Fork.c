#include<stdio.h>
#include<unistd.h>
void main()
{
	int pid1;
	int pid2;
	pid1=fork();
	pid2=fork();
	printf("pid1=%d,pid2=%d\n",pid1,pid2);
}
