import os

FUatr_IP=[]
FUatr_file=[]
SQLatr_IP=[]
SQLatr_file=[]
for (path, dir, files) in os.walk("C:\FileUpload"):
    for filename in files:
        ext = os.path.splitext(filename)[-1]
        if ext != '.log':
            continue
        
        #############################
        ##detecting webshell upload##
        #############################
        fp=open(os.path.join(path,filename),'r')
        fpline=fp.readlines()
        for i in range (0,len(fpline)):
            line=fpline[i]
            if line[0]=="#": #로그파일이 아닌 라인은 제외
                continue
            gawkline = line.split(' ')

            #file upload pattern(파일업로드 공격패턴)
            if gawkline[4] == "POST" and gawkline[5].find(';.')!=-1:
                FUatr_IP.append(gawkline[3])
                tmp=gawkline[5].split('/')
                FUatr_file.append(tmp[len(tmp)-1]) 
                print "detected", gawkline[3],gawkline[4],gawkline[5]
                #print gawkline[5].find('login')
        
        #############################
        ###detecting SQL-injection###
        #############################
        for i in range (0,len(fpline)):
            line=fpline[i]
            if line[0]=="#":
                break
            gawkline2 = line.split(' ')
            
            #SQL injection pattern(SQL인젝션 공격패턴)
            #[warning]_not absolutely correct
            if gawkline2[4] == "POST":
                if gawkline2[5].find('\'')!=-1 or gawkline2[5].find('--')!=-1 :
                    print "detected", gawkline[3],gawkline[4],gawkline[5]
                    SQLatr_IP.append(gawkline2[3])
                    tmp=gawkline2[5].split('/')
                    SQLatr_file.append(tmp[len(tmp)-1])
                    
if len(FUatr_IP)>0 :
    print "파일 업로드 공격이 아래의 IP에서",len(FUatr_IP),"개의 로그에 탐지되었습니다."
    FUatr_IP=list(set(FUatr_IP))
    FUatr_file=list(set(FUatr_file))
    for i in range(0,len(FUatr_file)):
        print "공격자 IP: ",FUatr_IP[i]
    for i in range(0,len(FUatr_file)):
        print "생성파일: ",FUatr_file[i]
        
if len(SQLatr_IP)>0 :
    print "SQLinjection 공격이 아래의 IP에서",len(SQLatr_IP),"개의 로그에 탐지되었습니다."
    SQLatr_IP=list(set(SQLatr_IP))
    SQLatr_file=list(set(SQLatr_file))
   for i in range(0,len(SQLatr_file)):
        print "공격자 IP: ",SQLatr_IP[i]
    for i in range(0,len(SQLatr_file)):
        print "생성파일: ",SQLatr_file[i]

        

        
