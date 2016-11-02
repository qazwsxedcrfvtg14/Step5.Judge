#include<sys/ptrace.h>
#include<sys/reg.h>
#include<sys/syscall.h>
#include<sys/types.h>
#include<sys/user.h>
#include<sys/wait.h>
#include<sys/resource.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<sys/syscall.h> ///////////////
#include<sys/time.h>
#include<unistd.h>
#include<ctime>
#include<fstream>
#include<cstdio>
#include<cstdlib>
#include<cstring>
#include<vector>
#include<iostream>
#include<string>

#include <sstream>

#include <fstream>
using namespace std;
double time_rate=1;
const int
	wj=0,	//	Waiting for Judge
	ce=1,	//	Compilation Error
	se=2,	//	Security Error
	re=3,	//	Runtime Error
	tle=4,	//	Time Limit Exceed
	mle=5,	//	Memory Limit Exceed
	wa=6,	//	Wrong Answer
	ac=7,	// 	Accepted
	syse=8,	// 	SysError
	je=8,	// 	Judge Error
	ole=9
;
const char string_status[10][32]={
    "waiting for judge",
    "compilation error",
    "security error",
    "runtime error",
    "time limit exceed",
    "memory limit exceed",
    "wrong answer",
    "accepted",
    "judge error",
    "output limit exceed",
};const char str_e[8][40]={
    "AC",
    "WA",
    "TLE",
    "MLE",
    "RE",
    "RF",
    "CE",
    "SE"
};
int pid;
int limit_syscall[349];
char judger[100]="the password you should not know";
char judgerpass[100];
char runexe[1000];
int rid,lang,ltime,lmemo;
char prid[1000],zer[10]="0";
struct timestamp_s{
	int year,month,day,hour,minute,second;
};
string int2str(int num){

    string Result;          // string which will contain the result

    ostringstream convert;   // stream used for the conversion

    convert << num;      // insert the textual representation of 'Number' in the characters in the stream

    return convert.str(); // set 'Result' to the contents of the stream

}
struct source_s{
	int id;
	char *problem;
	int language;
	char code[65536];
	int limit_time;
	int limit_memory;
};
bool file_exists(const char * filename){
    if (FILE * file = fopen(filename, "r")){
        fclose(file);
        return true;
        }
    return false;
    }
int Get_Size(const char path[] ){
    // #include <fstream>
    FILE *pFile = NULL;
    // get the file stream
    pFile=fopen(path,"r");
    // set the file pointer to end of file
    fseek( pFile, 0, SEEK_END );
    // get the file size
    int Size = ftell( pFile );
    // return the file pointer to begin of file if you want to read it
    // rewind( pFile );
    // close stream and release buffer
    fclose( pFile );
    return Size;
    }
#if __x86_64__
/* 64-bit */
void init_syscall(){
	/*
		%eax	Name		Source
		1	sys_exit	kernel/exit.c
		5	sys_open	fs/open.c
		6	sys_close	fs/open.c
		12	sys_chdir	fs/open.c
		file: 5,6.
	*/
	limit_syscall[13]=-1;			//X
	limit_syscall[SYS_exit]=1;			//1
	limit_syscall[SYS_fork]=0;			//2
	limit_syscall[SYS_read]=-1;			//3
	limit_syscall[SYS_write]=-1;			//4
	limit_syscall[SYS_open]=-1;			//5
	limit_syscall[SYS_close]=-1;			//6
	limit_syscall[SYS_time]=-1;			//13
	limit_syscall[SYS_restart_syscall]=-1;
	limit_syscall[SYS_execve]=1;
	limit_syscall[SYS_lseek]=-1;
//	limit_syscall[SYS_stime]=-1;
	limit_syscall[SYS_alarm]=-1;
//	limit_syscall[SYS_oldfstat]=-1;
	limit_syscall[SYS_access]=-1;
	limit_syscall[SYS_times]=-1;
	limit_syscall[SYS_brk]=-1;
//	limit_syscall[SYS_oldolduname]=-1;
	limit_syscall[SYS_ustat]=-1;
	limit_syscall[SYS_getrlimit]=-1;
	limit_syscall[SYS_getrusage]=-1;
	limit_syscall[SYS_gettimeofday]=-1;
//	limit_syscall[SYS_oldstat]=-1;
	limit_syscall[SYS_readlink]=-1;
	limit_syscall[SYS_mmap]=-1;
	limit_syscall[SYS_munmap]=-1;
	limit_syscall[SYS_truncate]=-1;
	limit_syscall[SYS_ftruncate]=-1;
	limit_syscall[SYS_getpriority]=-1;
	limit_syscall[SYS_statfs]=-1;
	limit_syscall[SYS_fstatfs]=-1;
	limit_syscall[SYS_stat]=-1;
	limit_syscall[SYS_lstat]=-1;
	limit_syscall[SYS_fstat]=-1;
//	limit_syscall[SYS_olduname]=-1;
	limit_syscall[SYS_uname]=-1;
	limit_syscall[SYS_mprotect]=-1;
	limit_syscall[SYS_mlock]=-1;
	limit_syscall[SYS_munlock]=-1;
	limit_syscall[SYS_mlockall]=-1;
	limit_syscall[SYS_munlockall]=-1;
	limit_syscall[SYS_mremap]=-1;
	limit_syscall[SYS_pread64]=-1;
	limit_syscall[SYS_pwrite64]=-1;
//	limit_syscall[SYS_mmap2]=-1;
//	limit_syscall[SYS_truncate64]=-1;
//	limit_syscall[SYS_ftruncate64]=-1;
//	limit_syscall[SYS_stat64]=-1;
//	limit_syscall[SYS_lstat64]=-1;
//	limit_syscall[SYS_fstat64]=-1;
//	limit_syscall[SYS_statfs64]=-1;
	limit_syscall[SYS_set_thread_area]=2;
	limit_syscall[SYS_get_thread_area]=-1;
	limit_syscall[SYS_exit_group]=1;
	limit_syscall[158]=-1;
//	limit_syscall[SYS_fstatfs64]=-1;
//	limit_syscall[SYS_fstatat64]=-1;
}
int checkSyscall(int pid){
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS,pid,NULL,&regs);
	int syscall=regs.orig_rax;
	if(limit_syscall[syscall]<0){
		//printf("\tvalid syscall: %i\n",syscall);
	}else if(limit_syscall[syscall]==0){
		printf("\tinvalid syscall: %i\n",syscall);
		return se;
	}else if(limit_syscall[syscall]>0){
		//printf("\tlimited syscall: %i\n",syscall);
		limit_syscall[syscall]--;
	}
	return 0;
}
#else
void init_syscall(){
	/*
		%eax	Name		Source
		1	sys_exit	kernel/exit.c
		5	sys_open	fs/open.c
		6	sys_close	fs/open.c
		12	sys_chdir	fs/open.c
		file: 5,6.
	*/
	limit_syscall[SYS_exit]=1;			//1
	limit_syscall[SYS_fork]=0;			//2
	limit_syscall[SYS_read]=-1;			//3
	limit_syscall[SYS_write]=-1;			//4
	limit_syscall[SYS_open]=-1;			//5
	limit_syscall[SYS_close]=-1;			//6
	limit_syscall[SYS_time]=-1;			//13
	limit_syscall[SYS_restart_syscall]=-1;
	limit_syscall[SYS_execve]=1;
	limit_syscall[SYS_lseek]=-1;
	limit_syscall[SYS_stime]=-1;
	limit_syscall[SYS_alarm]=-1;
	limit_syscall[SYS_oldfstat]=-1;
	limit_syscall[SYS_access]=-1;
	limit_syscall[SYS_times]=-1;
	limit_syscall[SYS_brk]=-1;
	limit_syscall[SYS_oldolduname]=-1;
	limit_syscall[SYS_ustat]=-1;
	limit_syscall[SYS_getrlimit]=-1;
	limit_syscall[SYS_getrusage]=-1;
	limit_syscall[SYS_gettimeofday]=-1;
	limit_syscall[SYS_oldstat]=-1;
	limit_syscall[SYS_readlink]=-1;
	limit_syscall[SYS_mmap]=-1;
	limit_syscall[SYS_munmap]=-1;
	limit_syscall[SYS_truncate]=-1;
	limit_syscall[SYS_ftruncate]=-1;
	limit_syscall[SYS_getpriority]=-1;
	limit_syscall[SYS_statfs]=-1;
	limit_syscall[SYS_fstatfs]=-1;
	limit_syscall[SYS_stat]=-1;
	limit_syscall[SYS_lstat]=-1;
	limit_syscall[SYS_fstat]=-1;
	limit_syscall[SYS_olduname]=-1;
	limit_syscall[SYS_uname]=-1;
	limit_syscall[SYS_mprotect]=-1;
	limit_syscall[SYS_mlock]=-1;
	limit_syscall[SYS_munlock]=-1;
	limit_syscall[SYS_mlockall]=-1;
	limit_syscall[SYS_munlockall]=-1;
	limit_syscall[SYS_mremap]=-1;
	limit_syscall[SYS_pread64]=-1;
	limit_syscall[SYS_pwrite64]=-1;
	limit_syscall[SYS_mmap2]=-1;
	limit_syscall[SYS_truncate64]=-1;
	limit_syscall[SYS_ftruncate64]=-1;
	limit_syscall[SYS_stat64]=-1;
	limit_syscall[SYS_lstat64]=-1;
	limit_syscall[SYS_fstat64]=-1;
	limit_syscall[SYS_statfs64]=-1;
	limit_syscall[SYS_set_thread_area]=2;
	limit_syscall[SYS_get_thread_area]=-1;
	limit_syscall[SYS_exit_group]=1;
	limit_syscall[SYS_fstatfs64]=-1;
	limit_syscall[SYS_fstatat64]=-1;
    limit_syscall[146]=-1;
}
int checkSyscall(int pid){
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS,pid,NULL,&regs);
	int syscall=regs.orig_eax;
	if(limit_syscall[syscall]<0){
		//printf("\tvalid syscall: %i\n",syscall);
	}else if(limit_syscall[syscall]==0){
		printf("\tinvalid syscall: %i\n",syscall);
		return se;
	}else if(limit_syscall[syscall]>0){
		//printf("\tlimited syscall: %i\n",syscall);
		limit_syscall[syscall]--;
	}
	return 0;
}
#endif
int usage_time(struct rusage rinfo){
	return (rinfo.ru_utime.tv_sec + rinfo.ru_stime.tv_sec) * 1000
		+(rinfo.ru_utime.tv_usec + rinfo.ru_stime.tv_usec) / 1000;
}
int usage_memory(int pid){
	char buf[1024];
	sprintf(buf,"/proc/%d/statm",pid);
	FILE*f=fopen(buf,"r");
	int r;
	for(int i=0;i<6;i++)
		fscanf(f,"%d",&r);
	fclose(f);
	return (int)((long long int)r*getpagesize()/1024);
}
void timer(int sig){
	kill(pid,SIGUSR1);
	//alarm(1);
}
const char LANG[10][20] = {
  "c++11",
  "gnu++98"
};
int compile(const source_s &source, int standard = 0){
	char path_execute[]="./testarea/run/main.out";
	char path_com_mes[]="./testarea/run/com.txt";
	if(access(path_execute,F_OK)!=-1)
		remove(path_execute);
	if(access(path_com_mes,F_OK)!=-1)
		remove(path_com_mes);
	FILE*file_source;
	int language=source.language;
	int rid=source.id;
    printf("~~~~~Compile code~~~~~\n");
    //system("g++ ./testarea/run/main.cpp -o ./testarea/run/main.out -O2 -Wl,--stack=268435456 --static >nul 2>./testarea/run/com.txt");
    char command[1000];
    sprintf(command, "g++ ./testarea/run/main.cpp -o ./testarea/run/main.out -O2 -std=%s 2>./testarea/run/com.txt",LANG[standard]);
    system(command);
    if(access("./testarea/run/main.out",F_OK)==-1){
        if(standard != 1){  /// standard 1 which is gnu++98
            return compile(source, standard + 1);
            }
        remove("./testarea/run/main.cpp");
        return ce;
        }
    remove("./testarea/run/main.cpp");
    /*{
        FILE *com_mes=fopen(path_com_mes,"r");
		char s[65536],t[1024];
		int es=0;
		s[0]=0;
		while(fgets(t,1024,com_mes)){
			for(int i=0;t[i];i++){
				if(t[i]=='\'')
					s[es++]='\\';
				s[es++]=t[i];
			}
			s[es++]='\n';
		}
		char cmd[65536];
		//sprintf(cmd,"UPDATE `sources` SET `com_mes`='%s' WHERE `id`='%i';",s,source.id);
		//mysql_query(conup,cmd);
		//remove(path_com_mes);
	}*/
	return 0;
    }
int mxtim,mxmem;
char path_input[1024];
char path_newroot[1024];
char path_newdir[1024];
char path_output[1024];
char path_execute[1024];
int run(source_s source,int tdid){
	rerun:;
    mxmem=0;mxtim=0;
	int x=0;
	//printf("\trunning child process:\n");
	pid=fork();
	if(pid<0){puts("fork error QAQ~");goto rerun;}
	if(pid==0){
		printf("\tstart fork\n");
		sprintf(path_input,"./testdata/%s/td%d.in",prid,tdid);
		sprintf(path_newroot,"./testarea/");
		sprintf(path_newdir,"./testarea/run/");
		sprintf(path_output,"./output%d.txt",tdid);
		sprintf(path_execute,"./main.out");
        if(file_exists("./testarea/run/main.out")){
    		//printf("\t\tchild process is running:\n");
    		printf("\tinput: \"%s\"\n",path_input);
    		//printf("\tnewroot: \"%s\"\n",path_newroot);
    		printf("\toutput: \"%s\" (new root)\n",path_output);
    		//printf("\texecute: \"%s\" (new root)\n",path_execute);
    		freopen(path_input,"r",stdin);
    		chroot(path_newroot);
    		chdir(path_newdir);
    		freopen(path_output,"w",stdout);
    		setuid(65534);  // 65534 is the id of nobody. (on ubuntu 13.10)
    		struct rlimit rli;
            rli.rlim_cur=30;
            rli.rlim_max=30;
            if(setrlimit(RLIMIT_NPROC,&rli)>=0){
                //if(setrlimit(RLIMIT_RSS,&r)<0){}
                ptrace(PTRACE_TRACEME,pid,NULL,NULL);
                execl(path_execute,path_execute,NULL);
                }
            else{
                puts("error with limit!");
                }
            exit(EXIT_SUCCESS);
            }
    	exit(EXIT_SUCCESS);
    		/*chown(path_execute,id_runner,id_runner);
    		  chown(path_output,id_runner,id_runner);
    		  setuid(id_runner);
    		  setreuid(99,99);
    		  setregid(99,99);*/
		}
	char path_execute[]="./testarea/run/main.out";
    if(file_exists("./testarea/run/main.out")){
        struct  timeval start;
        struct  timeval end;
        unsigned  long diff;
        gettimeofday(&start,NULL);
        //printf("Start time: %ld us",start.tv_sec*1000+start.tv_usec/1000);
    	signal(SIGALRM,timer);
    	ualarm(200000,5000);
    	int stat;
    	struct rusage rinfo;
    	init_syscall();
    	while(1){
    		wait4(pid,&stat,0,&rinfo);
    		if(WIFEXITED(stat)){
    			printf("\tchild process exited.\n");
    			break;
    		}else if(WIFSTOPPED(stat)){
    			int sig=WSTOPSIG(stat);
    			if(sig==SIGILL){
    				printf("\tsig=%i, SIGILL(4): Illegal Instruction.\n",sig);
    				x=re;
    			}else if(sig==SIGTRAP){
    				if(checkSyscall(pid)==se)
    					x=se;
    			}else if(sig==SIGFPE){
    				printf("\tsig=%i, SIGFPE(8): Floating point exception.\n",sig);
    				x=re;
    			}else if(sig==SIGUSR1){
    				//printf("\tsig=%i, SIGUSR1(10): User-defined signal 1.\n",sig);
    			}else if(sig==SIGSEGV){
    				printf("\tsig=%i, SIGSEGV(11): Invalid memory reference.\n",sig);
    				x=re;
    			}else{
    				printf("\tstopped, signal: %i\n",sig);
    			}
    			if(x==re||x==se){
    				break;
    				}
    		}else if(WIFSIGNALED(stat)){
    			printf("\truntime error, recived signal: %i.\n",WTERMSIG(stat));
    			if(WTERMSIG(stat)==10){
					puts("fork runtime error QAQ~");goto rerun;
					}
					ptrace(PTRACE_KILL,pid,NULL,NULL);
					waitpid(pid,0,0);
					x=re;
					break;
					//}
				}
    		int limit_time=source.limit_time,limit_memory=source.limit_memory;//limit_file_size=source.limit_file_size;
            gettimeofday(&end,NULL);
            //printf("Past time: %ld us\n",(end.tv_sec-start.tv_sec)*1000+(end.tv_usec-start.tv_usec)/1000);
    		int runtime=(end.tv_sec-start.tv_sec)*1000+(end.tv_usec-start.tv_usec)/1000;
    		//int runtime=usage_time(rinfo);
    		int memory=usage_memory(pid);
    		if(runtime>mxtim)
    			mxtim=runtime;
    		if(runtime>limit_time){
                //printf("\truntime: %ims, memory: %iKiB\n",runtime,memory);
    			x=tle;
    			break;
    		}
    		if(memory>mxmem)
    			mxmem=memory;
    		if(memory>limit_memory){
                //printf("\truntime: %ims, memory: %iKiB\n",runtime,memory);
    			x=mle;
    			break;
    		}
    		ptrace(PTRACE_SYSCALL,pid,NULL,NULL);
    	}
    	printf("\tstatus: %s.\n",string_status[x]);
    	if(x!=0){
    		printf("\tkilling child process...\n");
    		ptrace(PTRACE_KILL,pid,NULL,NULL);
    		waitpid(pid,0,0);
    		printf("\tchild process killed.\n");
            }
        int ta=-1;
        FILE *fPtr;
        printf("\truntime: %ims, memory: %iKiB\n",mxtim,mxmem);
        return x;
        }
    else{
        return je;
        }
}
void remove_endl(char*s){
	int sl=strlen(s);
	if(s[sl-1]=='\n')
		s[sl-1]=0;
	sl=strlen(s);
	if(s[sl-1]==13)
		s[sl-1]=0;
}
char user[1000];
int ans_time;
char step5[1000],yes[1000],langu[1000],username[1000],add_data[1000];
string rest;
int sp_judge(int tdid){
    sprintf(runexe,"cp \"./testdata/%s/sj.out\" \"./testarea/run/sj.out\"",prid);
    system(runexe);
    int rans=7;
    char sss[1000];
    sprintf(sss,"./testarea/run/sj.out \"./testarea/run/output%d.txt\" \"./testdata/%s/td%d.in\" \"./testdata/%s/td%d.out\"",tdid,prid,tdid,prid,tdid);
    FILE *fd=popen(sss, "r");
    fscanf(fd,"%d",&rans);
    fclose(fd);
    char out_[1000];
    sprintf(out_,"./testarea/run/output%d.txt",tdid);
    remove(out_);
    return rans;
    }
int nor_judge(int tdid){
    int error=0;
    char path_testsol[1024];
    char path_output[1024];
    sprintf(path_testsol,"./testdata/%s/td%d.out",prid,tdid);
    sprintf(path_output,"./testarea/run/output%d.txt",tdid);
    printf("check: %s by %s\n",path_output,path_testsol);
    string s,t;
    fstream tsol,mout;
    tsol.open(path_testsol);
    mout.open(path_output);
    while(1){
        s="";
        t="";
        bool tsol_eof=getline(tsol,s);
        bool mout_eof=getline(mout,t);
        if(tsol_eof^mout_eof){
            error=1;
            break;
            }
        if(!tsol_eof&&!mout_eof){
            break;
            }
        s.erase(s.find_last_not_of(" \n\r\t")+1);
        t.erase(t.find_last_not_of(" \n\r\t")+1);
        if(s!=t){
            cout<<s<<endl<<t<<endl;
            error=1;
            break;
            }
        }
    char out_[1000];
    sprintf(out_,"./testarea/run/output%d.txt",tdid);
    remove(out_);
    tsol.close();
    mout.close();
    return error;
    }

int ins,time_chk,time_chk2;
int run_ans(){
    char pdata[1000];
    FILE *fPtr;
    printf("~~~~~Making Dir %s~~~~~\n",prid);
    sprintf(pdata,"mkdir -p ./testdata/%s",prid);
    system(pdata);
    printf("~~~~~Chk td.inf~~~~~\n");
    sprintf(pdata,"./testdata/%s/td.inf",prid);
    if(file_exists(pdata)){
        fPtr=fopen(pdata,"r");
        if(fscanf(fPtr,"%s",step5)){
            time_chk=-1;
            }
        if(step5[0]=='S'){
            fscanf(fPtr,"%d",&time_chk);
            }
        fclose(fPtr);
        }
    else{
        time_chk=-1;
        }
    printf("~~~~~Geting td.inf~~~~~\n");
    sprintf(runexe,"wget -q -N -P \"./testdata/%s\" \"http://web2.ck.tp.edu.tw/~step5/step5_td/td/%s/td.inf\"",prid,prid);
    system(runexe);
    sprintf(pdata,"./testdata/%s/td.inf",prid);
    if(file_exists(pdata)){
        fPtr=fopen(pdata,"r");
        if(fscanf(fPtr,"%s",step5)==-1){
            fclose(fPtr);
            return je;
            }
        if(step5[0]=='S'){
            fscanf(fPtr,"%d%d",&time_chk2,&ins);
            }
        printf("testdata:%d\ntime1:%d  time2:%d\n",ins,time_chk,time_chk2);
        fclose(fPtr);
        }
    else{
        printf("~~~~~Geting td.inf FAIL!~~~~~\n");
        return je;
        }
    for(int i=1;i<=ins;i++){
        sprintf(pdata,"./testdata/%s/td%d.in",prid,i);
        if((time_chk!=time_chk2)||(!file_exists(pdata))){
            printf("~~~~~Geting td%d.in~~~~~\n",i);
            sprintf(runexe,"wget -q -N -P \"./testdata/%s\" \"http://web2.ck.tp.edu.tw/~step5/step5_td/td/%s/td%d.in\"",prid,prid,i);
            system(runexe);
            }
        }
    if((add_data[0]!='n'&&add_data[1]!='u'&&add_data[2]!='l'&&add_data[3]!='l')&&(time_chk!=time_chk2)){
        printf("~~~~~Geting %s~~~~~\n",add_data);
        sprintf(runexe,"wget -q -N -P \"./testdata/%s\" \"http://web2.ck.tp.edu.tw/~step5/step5_td/td/%s/%s\"",prid,prid,add_data);
        system(runexe);
        sprintf(runexe,"cp \"./testdata/%s/%s\" \"./testarea/run/%s\"",prid,add_data,add_data);
        system(runexe);
        }
    if((add_data[0]!='n'&&add_data[1]!='u'&&add_data[2]!='l'&&add_data[3]!='l')){
        sprintf(runexe,"cp \"./testdata/%s/%s\" \"./testarea/run/%s\"",prid,add_data,add_data);
        system(runexe);
        }
    //if(time_chk!=time_chk2){
    printf("~~~~~Geting sj.cpp~~~~~\n");
    sprintf(pdata,"./testdata/%s/sj.cpp",prid);
    remove(pdata);
    sprintf(runexe,"wget -q -O \"%s\" \"http://web2.ck.tp.edu.tw/~step5/server/server_get_sj_code.php?pass=%s&pid=%s\"",pdata,judger,prid);
    system(runexe);
    if(file_exists(pdata)){
        int fi=1;
        ifstream file(pdata);
        string fidata,fiout;
        while(getline(file, fidata)){
            size_t ftmp;
            while(ftmp = fidata.find("%I64"), ftmp!=-1){
                fidata.replace(ftmp, std::string("%I64").length(),"%ll");
                }
            while(ftmp = fidata.find("<windows.h>"), ftmp!=-1){
                fidata.replace(ftmp, std::string("<windows.h>").length(),"<cstdlib>");
                }
            if(fi&&fidata.length()>3)fidata.assign(fidata.begin()+3,fidata.end()),fi=0;
            //printf("~~~~\n");
            fiout+=fidata;
            fiout+='\n';
            }
        file.close();
        ofstream fout(pdata);
        fout << fiout << endl;
        }
    else{
        puts("~~~~~Getting sj.cpp FAIL!~~~~~");
        return je;
        }
    //}
    sprintf(runexe,"rm -f ./testdata/%s/sj.out",prid);
    system(runexe);
    sprintf(pdata,"./testdata/%s/sj.cpp",prid);
    if(file_exists(pdata)){
        fPtr=fopen(pdata,"r");
        if(fscanf(fPtr,"%s",step5)==-1){
            fclose(fPtr);
            printf("Judge error in A\n");
            return je;
            }
        else{
            if(step5[0]=='n'&&step5[1]=='o'){
                fclose(fPtr);
                }
            else{
                sprintf(pdata,"./testdata/%s/sj.out",prid);
                if(!file_exists(pdata)){
                    sprintf(pdata,"./testdata/%s/sj.cpp",prid);
                    sprintf(runexe,"cp \"%s\" \"./testarea/run/main.cpp\"",pdata);
                    system(runexe);
                    source_s ss;
                    ss.language=5;
                    ss.limit_time=10000;
                    ss.limit_memory=512*1024*1024;
                    //ss.limit_file_size=1024*1024*1024;
                    int error=0;
                    error=compile(ss);
                    if(error){
                        return je;
                        }
                    if(!error){
                        sprintf(pdata,"./testdata/%s/sj.out",prid);
                        sprintf(runexe,"cp \"./testarea/run/main.out\" \"%s\"",pdata);
                        system(runexe);
                        }
                    }
                fclose(fPtr);
                }
            }
        }
    else{
        printf("je in sj!");
        return je;
        }
    if(time_chk!=time_chk2){
        printf("~~~~~Geting ans.cpp~~~~~\n");
        sprintf(pdata,"./testdata/%s/ans.cpp",prid);
        sprintf(runexe,"wget -q -O \"%s\" \"http://web2.ck.tp.edu.tw/~step5/server/server_get_ans_code.php?pass=%s&pid=%s\"",pdata,judger,prid);
        system(runexe);
        //sprintf(runexe,"awk '{if(NR==1)sub(/^\\xef\\xbb\\xbf/,"");print}' %s > %s",pdata,pdata);
        //system(runexe);
        ifstream file(pdata);
        string fidata,fiout;
        int fi=1;
        while(getline(file, fidata)){
            size_t ftmp;
            while(ftmp = fidata.find("%I64"), ftmp!=-1){
                fidata.replace(ftmp, std::string("%I64").length(),"%ll");
            }
            while(ftmp = fidata.find("<windows.h>"), ftmp!=-1){
                fidata.replace(ftmp, std::string("<windows.h>").length(),"<cstdlib>");
            }
            if(fi&&fidata.length()>3)fidata.assign(fidata.begin()+3,fidata.end()),fi=0;
            fiout+=fidata;
            fiout+='\n';
        }
        file.close();
        ofstream fout(pdata);
        fout << fiout << endl;
        sprintf(runexe,"rm -f ./testdata/%s/td%d.out",prid,ins);
        system(runexe);
        }
    sprintf(pdata,"./testdata/%s/td%d.out",prid,ins);
    if(!file_exists(pdata)){
        sprintf(pdata,"./testdata/%s/ans.cpp",prid);
        sprintf(runexe,"cp \"%s\" \"./testarea/run/main.cpp\"",pdata);
        system(runexe);
        source_s ss;
        ss.language=5;
        ss.limit_time=ltime*time_rate;
        ss.limit_memory=lmemo;
        //ss.limit_file_size=1024*1024*1024;
        int error=0;
        error=compile(ss);
        if(!error){
            sprintf(pdata,"./testdata/%s/ans.out",prid);
            sprintf(runexe,"cp \"./testarea/run/main.out\" \"%s\"",pdata);
            system(runexe);
            for(int i=1;i<=ins;i++){
                error=run(ss,i);
                if(error){
                    puts("Judge Error in E");
                    //return je;
                    }
                sprintf(pdata,"./testdata/%s/td%d.out",prid,i);
                printf("~~~~~Copy output%d.txt to td%d.out~~~~~\n",i,i);
                sprintf(runexe,"cp \"./testarea/run/output%d.txt\" \"%s\"",i,pdata);
                system(runexe);
                char out_[1000];
                sprintf(out_,"./testarea/run/output%d.txt",i);
                remove(out_);
                }
            }
        }
    return wj;
    }
int main(){
    system("mkdir -p ./testdata ; mkdir -p ./testarea ; mkdir -p ./testarea/run");
    if(!file_exists("./testarea/bin")){
        puts("~~~~~Prepare Bin File~~~~~");
        system("cp /bin ./testarea -rf");
        }
    if(!file_exists("./testarea/lib")){
        puts("~~~~~Prepare Lib File~~~~~");
        system("cp /lib ./testarea -rf");
        system("cp /usr/lib ./testarea -rf");
        }
    int idletime = time(NULL);
    char tmpget[100];
    sprintf(tmpget,"/tmp/get%d.txt",getpid());
    while(1){
        remove(tmpget);
        printf("~~~~~Geting mission, judge idled %d sec~~~~~\r", (int)time(NULL)-idletime);
        cout << flush;
        sprintf(runexe,"wget -q -O \"%s\" \"http://web2.ck.tp.edu.tw/~step5/server/server_get_status.php?pass=%s\"",tmpget,judger);
        system(runexe);
        FILE *fPtr;
        fPtr=fopen(tmpget,"r");
        if(fscanf(fPtr,"%s",step5)==-1){
            puts("\nerror: Can't connect to internet!");
            fclose(fPtr);
            if((int)time(NULL)-idletime>3600){
                idletime=0;
                //puts("~~~~~Clear Data~~~~~");
                //system("rm ./testdata/* -R");
                }
            sleep(3);
            continue;
            }
        if(step5[3]=='S'){
            fscanf(fPtr,"%s",yes);
            //printf("%d\n",yes[0]);
            if(yes[0]=='y'){
                puts("\n~~~~~GOT mission~~~~~");
                fscanf(fPtr,"%d",&rid);
                }
            else{
                fclose(fPtr);
                sleep(3);
                continue;
                }
            }
        else if(strcmp(step5+2,"error")){
            printf("error password\n");
            fclose(fPtr);
            return -1;
            }
        else{
            fclose(fPtr);
            sleep(3);
            continue;
            }
        remove(tmpget);
        puts("~~~~~Geting run~~~~~");
        sprintf(runexe,"wget -q -O \"%s\" \"http://web2.ck.tp.edu.tw/~step5/server/server_get_run_data.php?pass=%s&rid=%d\"",tmpget,judger,rid);
        system(runexe);
        fPtr=fopen(tmpget,"r");
        if(fscanf(fPtr,"%s",step5)==-1){
            fclose(fPtr);
            sleep(3);
            continue;
            }
        if(step5[3]=='S'){
            fscanf(fPtr,"%s",yes);
            if(yes[0]=='y'){
                fscanf(fPtr,"%s%s%d%d%d%s%s",prid,langu,&ltime,&lmemo,&ans_time,username,add_data);
                printf("Prid:%s\nLang:%s\nTlim:%d\nMlim:%d\nAnst:%d\nUser:%s\nAddf:%s\n",prid,langu,ltime,lmemo,ans_time,username,add_data);
                }
            else{
                puts("\tGeting run error");
                fclose(fPtr);
                sleep(3);
                continue;
                }
            }
        fclose(fPtr);
        int error=run_ans(),ferr=0;
        int tottim=0,totmem=0;
        printf("~~~~~Getting %d code~~~~~\n",rid);
        sprintf(runexe,"wget -q -O \"./testarea/run/main.cpp\" \"http://web2.ck.tp.edu.tw/~step5/server/server_get_code.php?pass=%s&rid=%d\"",judger,rid);
        system(runexe);
        //sprintf(runexe,"awk '{if(NR==1)sub(/^\\xef\\xbb\\xbf/,"");print}' ./testarea/run/main.cpp > ./testarea/run/main.cpp");
        //system(runexe);
        int fi=1;
        ifstream file("./testarea/run/main.cpp");
        string fidata,fiout;
        while(getline(file, fidata)){
            size_t ftmp;
            while(ftmp = fidata.find("%I64"), ftmp!=-1){
                fidata.replace(ftmp, std::string("%I64").length(),"%ll");
                }
            while(ftmp = fidata.find("<windows.h>"), ftmp!=-1){
                fidata.replace(ftmp, std::string("<windows.h>").length(),"<cstdlib>");
                }
            if(fi&&fidata.length()>3)fidata.assign(fidata.begin()+3,fidata.end()),fi=0;
            fiout+=fidata;
            fiout+='\n';
            }
        file.close();
        ofstream fout("./testarea/run/main.cpp");
        fout << fiout << endl;
        if(!error){
            printf("Submit: id=%d problem=%s language=C++\n",rid,prid);
            source_s ss;
            ss.id=rid;
            ss.problem=prid;
            ss.language=5;
            ss.limit_time=ltime*time_rate;
            ss.limit_memory=lmemo;
            //ss.limit_file_size=1024*1024*1024;
            mxtim=0;mxmem=0;
            error=compile(ss);
            if(error){ferr=6;}
            if(!error){
                sprintf(runexe,"wget -q -O \"%s\" \"http://web2.ck.tp.edu.tw/~step5/server/server_set_running.php?pass=%s&rid=%d\"",tmpget,judger,rid);
                system(runexe);
                rest="";
                for(int i=1;i<=ins;i++){
                    printf("~~~~~Run %d %s td%d~~~~~\n",rid,prid,i);
                    error=run(ss,i);
                    if(error==0){
                        printf("~~~~~Judgeing %d %s td%d~~~~~\n",rid,prid,i);
                        char pindata[1024];
                        sprintf(pindata,"./testdata/%s/sj.cpp",prid);
                        if(file_exists(pindata)){
                            fPtr=fopen(pindata,"r");
                            step5[0]='n';step5[1]='o';step5[2]='\0';
                            fscanf(fPtr,"%s",step5);
                            fclose(fPtr);

                            if(step5[0]=='n'&&step5[1]=='o'){
                                puts("By nor_judge");
                                error=nor_judge(i);
                                }
                            else{
                                puts("By sp_judge");
                                error=sp_judge(i);
                                }
                            }
                        else{
                            error=7;
                            }
                        }
                    else{
                        if(error==tle)error=2;
                        else if(error==mle)error=3;
                        else if(error==re)error=4;
                        else if(error==se)error=5;
                        else if(error==je){printf("Judge error in B\n");error=7;}
                        else if(error==ole){printf("Judge error in G\n");error=7;}
                        }
                    printf("err :%d %d\n",error,ferr);
                    rest+=int2str(error)+"@"+int2str(mxtim/time_rate)+"@"+int2str(mxmem)+"@";
                    tottim+=mxtim/time_rate;
                    totmem=max(totmem,mxmem);
                    if(error==1100)error=0;
                    else if(error>=1000)error=1;
                    ferr=max(ferr,error);
                    }
                }
            }
        if(error==je)ferr=7;
        if(ferr>100)ferr=1;
        printf("T:%d M:%d status:%s %s\n",tottim,totmem,str_e[ferr],&rest[0]);
        printf("~~~~~Sending %d status~~~~~\n",rid);
        sprintf(runexe,"wget -q -O \"%s\" \"http://web2.ck.tp.edu.tw/~step5/server/server_set_result.php?pass=%s&rid=%d&pid=%s&status=%d&td_count=%d&time_used=%d&memory_used=%d&result=%s\"",tmpget,judger,rid,prid,ferr,ins,tottim,totmem,&rest[0]);
        system(runexe);
        system("rm testarea/run/*");
        alarm(0);
        idletime = time(NULL);
        }
    return 0;
    }
