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
            if line[0]=="#": #�α������� �ƴ� ������ ����
                continue
            gawkline = line.split(' ')

            #file upload pattern(���Ͼ��ε� ��������)
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
            
            #SQL injection pattern(SQL������ ��������)
            #[warning]_not absolutely correct
            if gawkline2[4] == "POST":
                if gawkline2[5].find('\'')!=-1 or gawkline2[5].find('--')!=-1 :
                    print "detected", gawkline[3],gawkline[4],gawkline[5]
                    SQLatr_IP.append(gawkline2[3])
                    tmp=gawkline2[5].split('/')
                    SQLatr_file.append(tmp[len(tmp)-1])
                    
if len(FUatr_IP)>0 :
    print "���� ���ε� ������ �Ʒ��� IP����",len(FUatr_IP),"���� �α׿� Ž���Ǿ����ϴ�."
    FUatr_IP=list(set(FUatr_IP))
    FUatr_file=list(set(FUatr_file))
    for i in range(0,len(FUatr_file)):
        print "������ IP: ",FUatr_IP[i]
    for i in range(0,len(FUatr_file)):
        print "��������: ",FUatr_file[i]
        
if len(SQLatr_IP)>0 :
    print "SQLinjection ������ �Ʒ��� IP����",len(SQLatr_IP),"���� �α׿� Ž���Ǿ����ϴ�."
    SQLatr_IP=list(set(SQLatr_IP))
    SQLatr_file=list(set(SQLatr_file))
   for i in range(0,len(SQLatr_file)):
        print "������ IP: ",SQLatr_IP[i]
    for i in range(0,len(SQLatr_file)):
        print "��������: ",SQLatr_file[i]

        

        
