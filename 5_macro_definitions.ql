import cpp

from Macro m1
where m1.getName()="ntohs" 
   or m1.getName()="ntohl"
   or m1.getName()="ntohll"
select m1,"ntoh macro"
