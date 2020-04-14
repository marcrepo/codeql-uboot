import cpp

class NetworkByteSwap extends Expr {
  NetworkByteSwap () {
    // TODO: replace <class> and <var>
    exists(MacroInvocation m |
      (m.getMacroName()="ntohs" 
   or m.getMacroName()="ntohl"
   or m.getMacroName()="ntohll")
   and this=m.getExpr()
    )
  } 
}

from NetworkByteSwap n
select n, "Network byte swap" 
