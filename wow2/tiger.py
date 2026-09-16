#!/usr/bin/env python3
"""Tiger/192 in pure Python: the reference algorithm with the original 0x01
padding (not Tiger2), its S-boxes checked against the empty-string digest at
import.

    >>> tiger192(b"").hex()
    '3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3'
"""
from __future__ import annotations

import base64
import struct

_MASK = (1 << 64) - 1

# The four Tiger S-boxes (t1..t4, 256 u64 each) as published with the reference
# implementation, base85 instead of 1024 literals; sha256 of the 8192 raw bytes
# 364d73427379144b709fb0565ba1536c2c32ef9b02ab6201b1aefc30857372ea. Not a key.
_SBOX_B85 = """
UJU8?e6gwm?5IQH14}}z)BM#9<6F&gI)C~0lbZo;laU|N|9F|r;wgY|$)R&~!-Fc4Ycgc9a9EK9?
mmb{=IjG;1>>yhTvMY6xM@Mfe8k?3kyPhQ4D=1$-}Isi`o2x47;m=_YOB#&Beu-O|KcxKAz^Y89+
I6IZ;VJ9$_D`2^!dq4$3ar)_U82_wntg&+j)?Ml8m0o#f2D8ONMW$9(In`eZjR-j6yb!!DBEtCuq
-UZpE~lJ;?{Q>a}(bb`FAlLfn7w#++Pa;6gJbc%V4H1br@@JTz-x#tsW$>x#nith`imU)T<8<xkt
Bfg)LPpY0FMY5Hdw+eKx$_>)ro3t*@6*Xeo4P8pK{l1KuEv%s7!J5%|j6LysqY=cvf@q0D=iqCD^
R}VLOdg{IyW{|m1$`^41HA+HsmkP6Ln<ORU0x#+G;mRBa2irM!1uCTMoV4@Ub1yhiKfYGID7&yjS
nc{ngCD;UTs?stX`x@&w&d`NnVGGJq!{iq5Jbtb>gXms`68&mD-aO1I}+v$G4CD}RI%Mz0J&xS2j
<|#K!z3I&!fX8m<LXX{WZlSl?@G(04thKb&X>+)tyE_&-{fzOgiF=(t5GPE^0n%{P42M%|DcD8kb
-wMg-#$;%?qOu4NbCD)S;@{s@CdwF^~UDx&S6jj8Xcrwzo07N=3egnWjaZCC{nQz)YSh3@~{cJE#
+CeZuL0n(6(%aroEb=mqV^<<Rh6h0H*uM@D8Sji(OqtT}Z84>m{QT~;0zy>TvPO~c6(s6u<Gv0gc
J~<d=Zf$gVDKl|hI2oi{WOb=XxuzR@XRQ5u8GM*A0zCyw#3O9pP1XX?{z)8IaTO*wV@*fhV$gHs!
$w7_VE9#(G|rEb*_5lwx*HZqXm1X8FeH&<9Aw4<=B3DPE8TrF6(uN#8*oblLTlPAZ3)YP!8bjyZy
d*Ff<p-5RkBg*$AB>_yo<n=FSwH5y7Mxoz{qG^Rs}sAhRg(2k884D<)pu>w9dM-3X6n6GF?QfbD}
h}f!JE8@Rp{$Y}F{WW$gAON>cQYE>YnOTGIwqo!6aCd6&+{`UQz4Gn)`TTPYbJ%v7Lri$|&Wuzo=
_`SK(w#2al>eKnIgi~qJA!WyVJzZPJ9@%zL__2XxD-Kq~Bmg|d?V*k8)$$7z#l&y`Y4doFjx0oM~
ks1;wu8!nk2$+R2t@mP0>*`$ZMWgHN&V-h{Ub4>hA!7Hp4B|8P<dcG{2Hz~Bq%7{GEFfB#v5$((M
}!N{qgj}jL{fI27XT!ou@=>+CdXa7KDyTnIooQuRmw}{V}M6&{W^Lb-JWLW2*#dKBdST!q7_#Tl<
|**aYcO>B1{26GGDds!Y*z)p<G@MVZ-%xdy*-DHssdBtDh6CFF?;ssqtM6$ls;DNZE@%e)m7USJR
-SMfP+bB`(pTf}nw3Ql9;0NqT61&X5c)#XFa}zP#wdUvvrOya50J*0b8?yLUH2wQlgPejH}e*w3m
>H6M7P{I3=(N+=O6A03JMXHWd`+6t1(UBc{hQ6{0nA`D@!inmtN5UAjm4~OS3A2^y?FjY?J?P9If
Clrk~=;bBSF-EV)aC?_!PuDr#vWfVaL($<>zc4=|mprD~({+}bsQEPWPgQVKh*nQZbjxZMt*+#<s
!Ydl5=|*@WRcMD(J?@1i7L2PYYV<%T3Xrfn)32#=@Pv!=%4@o6L8a;23iQ#1O%Hu75;1%^T9w#``
+`-O)OLi<6O;!gCWJVL8f9v+_yE!Kep43ruY{$KwBYODOm})a)pdL@7kRCUAg@D6b6g|^UXRM&8!
p~Epxj7@^RFJ7TV~Q4iTflxPltLAaV*r4k6z;4GDg?onFv9pS|>6M5I@K+V)SK_@&f?;b0xwM~;~
ngu{ojh8VLO65Kxi@5>CB%sl?b1O1yAkhO2*+*eGRM*T83Wv%gipaA!NS%@8@Xhg<Y_F-Gpw6HIB
7<UAj(5_n*rn*o)OkQ<p-?Z2we@-Fk^p&hGQ@`CR2?4#d2|2DZP&AIPH}y?}jdCDDsGT7C_apwEn
;mJMe~qrhh|)#`TX<>VB*jd7g%ip(0e{#brHXqK4?w%lzLp1AW-Bfy-mt<YK_(J5vilyby#jXy=}
Y*mj=Q?ld&V1NIWbs~B;YoH;4R#X?P#C$R)IWV5mE2k_cqe^fF9C{S;Qxo*Ix=}mI#WV%c<)LLyt
<!p*C<2OIELey_y+#r<%FIQt8M)$R3}Sxq(V~cTiA_@Hk@ykFUx)cxQTIP(QQ>cg*bdNvlLknC^M
D<krJGj1Uyh(bT}4pvY?=3%~|Mi7nU2REVL1EJHk8vu5LG@;56GVcjFS9Vdj?c_*t@uO$`#u;GKg
sY!kz)Mb48)aOWT=iu9Go)_6ghl1Y-G`&;ZnriAI3Lqj@929Qj?ohXk8(n~ZH|SWOrN`y3Ji@V0Y
MFoH(C~E!`+bJf8i|N*-gD;AC2Y8_p6faimAFO0)z$GZ=V@~8ElNYXIQlX9>}Sh(oWDCVasxZ_be
t#qHe=ROs!sa~tTSIwhvCekna!o>yD%*tfOJVykZp(65mzmZjsv`rC_x$@NM_}N9p~cKw=#E0I&1
@UtMy@H*?zW(q5|si*p==7J=A0r);lZbAV}N`7Y{I|dZ&2pV28o$I3b}0TE3>{n0)xOr6QrVkZB7
PiC{cd)m<MsF3UztG?cf=+pRL$^{*8m<Z$W;@r*}4XQpM>nT;o_es%lAk_K)qhQ<-!7CV0p@r3K$
1nOm`1okd(v)|zG4-bw?QM$Z6`0nkc9yg>8Dhf~hDTK3Js2x7&;v5^gg7}Zz4d_#YUQk8N7YEza0
GiPl0fF<S?a!bz^2&#ZQGVwOHc`a0I21G<`OJxs^p{uQ6dhUeoj=n5&Bc|4BHBGvGb#m{{ed55c6
$%oLFP7x2UCtgC3hkf`m!z-Mt@)8{@D|360)dB>Tc(f7gXG@kBQO7zY^I48})-5`l_)p*|#d>mM5
(7tn1SJ*QcXE#k~6pZ4*`yg$!+)-QkINs&siOcqKK{o4|?(30>l+(Cx<Rvp7M$aGvXNzP}2RTw=m
c_0XlFqmU8{YvWYFE0g|W|5@GkeXOVvMKw1y)ZF@VkzRz#+#sDYU@Q297%ykd;Vi~^EMz3nt)dBw
Cg<51YU#ny3{a^{n`(Gk^FvHyHUk0<BG_i@N=JLa!m69>;~H~nSOSFLdS)hqrR>U)c2?A9wXJnXT
osfZ-#>v{nEe242F-N0{B9^wuSBOGM>L3DF0NtcuAnUUn&9ZJ&E!D7W%d|Ry9<};WEtNx>q~BOVw
V{y2LL;8r!epJ7T7UHzNQ2fwY7k_Y)jaF!;=?emVN2=ckLm2b8Go7F$QCI^z(1%NQqLe`1qrS^4H
r_V-WmI=iJH`-NsV-y%}5p(`wXYU5|!nY8W2REK!|0u3%O;!eV|l*RkAp>gQSGZoZmya|divOLL#
l`Q=)3sEbvK%*Q`TMXNzDQ^C2gy;%xJx>y-9lfy<|3$QJP<*+u>E1MvZpYfh$eNSL+B+D##;)<HN
$HWxKwkq|^dvX!Juh}O@O|u~Z3=NfjA4jclRzq)fNoZPOLe#DGdX>3=nc#;`RpYKu-=WVcR@E>4I
wqLd){hL>O_KD;Iu}ZHJ<6HSJin2ztb0fPEy0l1_Hk3~lyGQXC|nwYq@V~l3dz&OfMw7ZH;{i1fA
amf6TA5tLnu&98*ja_5<vftqZ@V{J0IfW#4r^NiYzy$Y0g85X3n+#5l$H8A!c*EfZK~<3r$yx*19
QuTmI%HK4H6oKamH#5S$zbmo2ObdF#H%SJ%ZmHI3!N=wXlZl6V2@8p0f#ocr(8tM`=jCVg_513qh
&qGRBrFr1)Dnu|)Ev=0dY)wgOtz=|eUpz^?+(L%rNEuHQ?a;ac>$Vm?~K^sDc0&=p(oHhV_z@Ehl
B{Vh5Nvuxq*eL<;P9#wDw%+v0<wnek_hXWnW2^ozctv_${<(aQHAZ7jWcS!x0Ld-C6?1w*93~|ps
>IM2P>xZPY)Fzh!_?QJ;Qq_Bjon==Al7w!VQgFD*p<TD87l(<(`mC{GC}0rUuZ(k5LWixx!v;y@J
Qjc9nz$ZZ%NHB=KQcAG48NfBas^{2&45FxEF)6&(fxx7#^Ic$lI!FR~Tyy<NBErsp?&}=O++<OL;
5%>svcSe=+0)rqDTAGA)Hm{C^<(?rW~qbkoOyvVxW{b+p5jp$X%<1)sDNd-=nRXE`bOFG8u9eE)V
3uog=s?q@w_99O^ip$+5iSZ56%x4GVW*%7wMqE~Eth}EyR;ZK-rgszZc{iVUI-b~+=|2jy;(OZfI
H$1vR!E6>|KyUZ5Zc@07PHhcu1AqwO9Wfo3$s+}xk=A_7Bq;1f$$}&1S%X_wm6?dd4M3jyXcclr%
RYk9F9-&LJDC02%czDU2q}H4h;_IFM9rTj;L*J(_w|t*_5lI}IiF_a-b(O{A$%Qr&gGofDLi6ju?
xVKkVI%Bx&x)1hw+=Mjs;kxvFszf%pO3y0pD1fJrrN4Xy|aDo+I*oFo^L_gArsJv}M&40v2#mbTb
p~30^2a&pi&6QwhkqR05M(ZQ3x2K$-G8hZAX2Ka^Fegon$i%HCd~py?|$Cm|Fm`+83QA2;xJC?Zc
MQ1m$hi-uku@Hz*(!IloeaRtb~BQ7Fng$QTTu(g1W)T42hfxDC8iqo}KxCD!#(Be92Uo+LM?6gQ+
%ApoX89Q|S#F)M`fdO|Vt)x^u=!bddx#2U~6cFJk6QXJ&p2Z9&U|$+-bzezwcki!Y`%~zfzdc0vr
-sL^f|{~(VMPQ9UcEBHW_r9>vdB7Tj8z8nDtF1Y#yR#u+BMpr>F;eJ73O;!#|&f<CskZlls3eZIe
2$QVvYmqX(T>c&hxAJ(h}1TjdmV%#!}YKgSbQiQiVUGTUrakomxY~GnVEW?EQ=gq>Q4MAoP|VJft
LuMyKv>rY~VPS`N?oWwA_aO8cvz1{|tGYk6YvZ^BJ~51Z{&j?B7jJ|(--@Bg=^Po1K$mAoY`j5zV
$i>20vRPeTT#Y)%SU4TU^yuC1hiIPp}aIb+p+W;}1+HL<nM~KYdpTmu_ez+HnQiV7YLbkC$(hl14
srgIQ-1^Q$=6*aw4j>W}NXK|OPsseAyLN>nav#m`<j*)Z1$1fbOit_!e72`6?J~~g^Gz?T5lrePL
(wzKyjXt6Oa$qq@BB2`lQL0XL{#MlRb<Is3gmq;k3rs0S>oMk8ncWzh6;jJG^n&K=^Al_9;pzJaf
3;*xA6B(d2yG(t1c?m4qT0@m%#cWoAcW7FU+6xfs*oX#?^mFKd9XNX9lC_W6u22<4c<?!n^yEOZP
w8X1Z|x(q*A9)RPXEdEx`1abD!GckIo+m*j;xavrqL7f|<J0;&qP;J83I@ChT-d4-8J&>H-X#jCR
73zEi`a*<j$V?nQG`zLYA+^cjULH}|}rp`RGrDiY)Gf7JD^_nQx%?g)|Uc$&R;OLf*M_q?@BEbIh
-H>4g5c7NNkrWTRuCT53l8Dt0h4@gL=uNj+gGhBrVH{JD_D?mV?#9xA<hud~nC<O-1tj~40_m286
Lm1G?Q$m<fHf^04Z~}W!jE(7CPM^ckMC4izB}DoGE!WgBSu^@&r_<9XV9HAQBBgpB&MFG?$1#mPk
t_j3J)R^WJurylsP%hxBP~1q%6eQ%;y7&Bhp%E+wm`}vV>#??0LWMa9y4LR2WE{-MJH6tqB$Fb=2
?`QJBXL2F>dW__sP3k!Ot6<nHrQP<$BC|AJ2Ck`Z0WqHL_WOrh?EU43U$vA%^gDoKnVcpVwt`Rjz
Ix@HLWbd1oVJ7kYhB76wpR_RiRjjj;Hjmv1K8jkG0CU*olszp1^v^aOB8Qu--9BCG<2QEf{lQGoB
I2oo3ZHJ}BK-iC^ANsi#7*D4>7qN;M9|D}om@nF^7U)V7tAGVQyIN#(w*@<2_VRUAzM=sosf&J20
CX=KQ`zWo16bD_Fiv)2mDp~7JpgZ6|0Y?nxz@#~Jt<|MO!$!2P4Lcch_5sMUnhb`0SJOW2s0Gqwf
P#FK>iK=YdPC2G@~U$QnCTFVt(g}T47aYpPp~S2`tl+Em}o|g>*+rsoux(x}Kvm!L-j~VpP0t%s{
Y%uqLzp$W)X&jMx8%o@(`0#w+xh4V1zyEp7>G3E%gazf#yb9^j@K3$)bR%bck~S;gr^ub7#ohB4U
(=#^qNbN8Y88yHAy9SV9C;#ce+)fyo7YD8y7b?~sy%Ig*8cn2wHPapHR9?>Gs);@6}JITW?r@>b+
FCRaA!>mTj4)v-6{gb%c&z}omF4-S5);j7)VfmP(>Vs;FZbI0o++1_Fbh3${5lT`XbF=n`NoUE+<
p_uol+&BB$K(c?45B2Pet+$+r$jdE-s%Zu-VX2R)A1f`w2yh|Lw(7)qbLk?gxB(-Z&sIKN0x+pod
#dF=Hpv>5O2PC?J#5c6>0~1=MCoW(3^{(O72T5PKmh3KBiV`^!_xuSrZZh`~x>A_?f><$S|)AHF1
DBdT1B$iF&8dX*EKg>#4!<nSt&tD0X>_y?P(rr8gH{fcmKkJVR4Y*`a*jQw)pxcgt*uyxiG8AV(X
ie33xF-`vspLIKcySbI269sG8L17$Ju#pn1VIdkLZL?S8!OQ-cv*QJMCE}57%#7rv)JoZ?)?0b>l
+HLq-{J3y3cHOlpyK=4&D>eXkPRVLlkNY0R+7i(kC#3qt4#OL1Lvb?95o09(1~TO^jy6IumZL1-F
%CF!@pi2WmRyaMHl=OBF!a{=(&6VDKhgil;oD6BX0CX3M&^440Y8HUZCL(0t+h0}@Ruv0$uwUHs0
`L6MYeh*(RXwK^TylUP14HV)D$jC>mCZe+2*yqs{uoK_i%nH{XhjLiY@fs!6Hnfz>Wt2hhxF?8d2
Wm3NxC$QaZbSHDrCNS9oc6GEA-m7K2Uz661KSAP}PG@*uQo45vYz=0Oqa7;NAuC~Hrcy^ONbgPm?
fY+tt~e~m#+j8;dwjy)LWzpV?{L|_(Qe{CQRKFZ4xIiy(Pyucl@Mi)AA)6LiQRH(|woE;`Th%&5v
ER?z<WWtbkxI%zOBvs`XpE#mcc1OP8pe?IsUYjUQG5x!boGXSzWfK&g1ju}}lgE)OHXAI0*xwWTR
YtK+d#U0S2fE816kpz4okc@oiLCI|@%yM#09#%h*aYgA^RxZbsDUA32ofq+LDRhHisj5hh9wacq~
OM+{>4O*4`R<{WzaJXp`0O~NR6aaA;@EGtX@9EuMKx{I*W3t?}y(Ydrp(r<%T{QwgXk;1l1YH`yu
1XroUjUvrw86!?vG(>S$ig$FYNy8IT;XY&Vs{)ja7v6Ro)_-!9dzgm|F967^s%$q-`WqlP`a&QUo
Qo1G>#`nAo_DsFuYGgp7umtyEy=dg{5A@YtXeyXL>DF6UfMH>dS;flbEI&hL~D;&eZLhmK7Ygx>c
Rs>Wc+jAWXnis^``JlE0U_3ppqObk$#Fmt_TL;MZ<J24-6vxG!G*ylvI2OHlY9vtjXch6YDZB!e`
n>w>8wDfU^5txKd{dL$uqffGt|?3Ipgl=C*Oh2NENkDjH-9Y>CB3WsvBX^vSPOx0kSd7xH{B26Tt
A9YwaQIWTP0D1hlQRz;xxS(fr2SO%j`T|Z(E>r%0A&j6#@{ptm0WO(Ruj~P|W${C)zh)eT4B1T9=
Yu{v+nokl}6CNPt#*xYjaIZXq>-&bKz2N=x=6dMYP?_ZDf4i|y}|RTa)m^uOIVCB2zTUE7sQz%PM
mq5ad6whLyEno1h`vbm&2X&DT2Xxd4Cs)^!(U!bvr51M9Vi}Xa6egCs3vvszOTw!a>mA>n|xgbwx
f>~vCf+I0+1<yr3afswvR}sQgnV(_5>FTIJV8puW&B4I(>2FL$9BC3{N%ovUa1UE1?>pSno{Cq)^
<WNdRXj2#g<uX_^;sMGsli4X`j1R}p+(}U*HtOoSy9Sm!ml;Xb_&}CMLiLze#h#84GOHbiujIF|K
odEQ=*=rR?SGPv)>IvZ{%F`dZx3)UeMzE*w4;R@HLsU5O4K9#u?U}g4QAnX&~Qp3P$}GK<yBPj?D
OMr^;?Rza+@kNpOK0SUn_RqGQ3kwycW;GR#DM!iuBWs}S_6TmRjEOM(QbT1joKl%I?(Pp78g<LKT
s5{38Flh{CIh<{7{+P|bK1R#7Qd@|7&#i4Eqg=QKyv}S45eFY&B!=-&E_s=?{lbF?%fg-@o9L4Zt
+lgWS#Jn>-@oMHw7|R9V>YKS89nD<-512y!r&PGGpG%E#YHHMbjQyn|%%~61F}>s~m4p=2M>r(QU
zhsF2gF8L9_@xm1PiwwdE3n>e?fEg;tR0CcldxIMUa(T0PAq`|J`ePq}JKiIG#|>0;hju01xZy25
(??&j!pL3jc<pi}KmzV!{~7T`*eMR9_-8haFo-{<X|#7PU_;Ai68p*|~Y9r9&-|4IG41=%f<ANUD
B2-yJXVM-Co%a|yKy<_z-hLbv~&(P7dcIW8&&11q5xl>}uuBI{roxVR40{uUf1ZUH9vFvGx_adtk
HWhNEvaFsTulrh!<hsm*&gYa}v;aswij9I#H_Cl8nffY)5Y>cn`=_OeWPIPG4Y;k8W8*|s_cd!bP
VK2m5+q+?EXBCC;`#w>V)#-ztOLCO-jbsU2nBj-${R}sC#?!GhT_p{?Gvqbg;2RS(Lb$5XuYQZPP
$~onHLIgU?!=dw(3uw?Nqd@tK}5y32ZK8%rfh2c^p!7l<;DmsKo@e7?%9>6RJV#MJ(O}URrf-q2o
iW1PBSqqkz(%Ze2uA33A0^hFNVWa^RZK17Z3)$CqF?zxNQDLS^5m$k~iQ#k6ySgHvs3)7~#CF=PA
CY-7$pTT<%2WK8Nu^8yk3v=kU^?cudKqC<nH8C@w)cET+k?^Ij&Q#Res640po363*e=)or#qH(O^
)(3w=`7Sg|gG*XX!iSrfg{A6zr$P-(OVZQHl9X=-%w}RZP7o8ac;J-lK_+jAZSCZ*Bs#<phX<}0P
`BptfI`+GZWNxBE6+Z#+n8==opMEf?%y$75q$f<wNHZPEEH6VF6QFOOj~^Z0*4?K^paN!K$FdyEW
UDvQ)6x7Ta*mUmcJvR9a05>4Ex`jl+WWHpnutU0(#{L6Lr?qbBZ<o*Z8`Tm0Sz{3BH+~00ybWSOn
4vAx&=4~M)guS6MEq@IJU=%1$0Q?N}-BpoU)R-&8_-u$Dim7G@dgE2~M3~xg%L0De15AUnWWq_JA
~Q9E6*)DmuUJt+bJks5lwo!_&q^`0w9W@~SNM3u^!`c<yy??|JlMsTPSG)LNwxQ`G*1kkTpg<^Zr
3d&2QTbigB+bao#rU{iF$qwID|y^$8VWAvDeYUZu+JjuKimxD!ZJ|TsO5l2lY@O>AKQ7J!AwR4-a
Yis$#Xn__GuCU5uJC;2T6x*RyR!jViT;3FJHSvk}!P-$yuV_AK*$+#NolmIA(fOcKKj4uzfR2aZM
sC<%P;t<i4jOSh5R*;}vSkQbE@<%NAN>1Po8Mj#<6VvFdKh^lvHh!YoO|cK;hniIBSp_M>cH$Fp~
nRnQrDzea(u2<>-Cm6+;xw!J&$9mj)3W_jWs!+ta1y$k^0`Zk}XMM{Xtc0TTL$c=-$R{e(Ju&t5-
iY&X88x)@fIBgcLbKrb;6UoelUXfKd7N74oxsq8a13O&T;&5uB|t1z7KUr6N3cGlrH28dk?eHol!
Cp4t=nXiTPfn=NJ9?=-_Zf2k)-^cQR9AQEDB3w_O+i9>gmf@kgE%3JR9{CUU#Hg%sswr!HNIhxQ0
h{bv_u&#q|As;w~O3LN|B`}}SVl@9|`#b&JBzz!p>*DO<)3)|X-U#Z)zD=2&#EY7+m*uQUx|avfW
=D*(bt-(tbCVkrSRRvM&Mbnl3>>-%xm9(Y(h+@=-LHQV<dSX1tvlK&yzIhMan-@1B>wh-O%ugfPb
XqqQR6xsCV|TVF31Pz%YWk&842z9$wmOk`PfM^WBZ8X?VHblp7CrEnp1%oS0vSI_wxf$sP{*%_2#
z~&zyeL-p1G48oMY0L0siTnNHhYCDcc@F#M{xD~J(YDk0M;yNe0+vz7ws6za8)S_0iyA(VS(wXBe
%z~@-|0ZP4tOlQ-HJGt{q-=r;`DM+h~G9JYIQY=`ymW=ZQvR&AJy}i-OgRX*L!9ujVu$tPXYv^CO
KdEsyX9O;?*itb`$yif_9#piKhDa*DW@(PoE!?7&D}_9gtPw20d#LganX!l?zBf-B`Urr01Lagr$
k1>f)K|`a?5&VgIywf~Cp;?vzoIaJgrly0zyl!dZ88GJhCr!leJH1cihA`h%U^oMdFShS<V0w->A
c(p543Zm;tp4cZg?8kp!Vp!&AOb2FQa6^ywPfxi`QnBUg9CEJj3PXs$&q4kd0|bM6(!}yNVt@u7_
mfwA?$1G5Ni(8P&UA+@M8c%4L+BCjKaf>`|OQU;$kow@FZ;20-LZvCDS%<#24j?JHI9@)#09qc&P
_2nP(yL|~XtbrenK4k)M&L)li%Wl&#J*O4W`mhTF3@gp+GAEje+Z#kgD
"""

_T = struct.unpack("<1024Q", base64.b85decode("".join(_SBOX_B85.split())))
_T1, _T2, _T3, _T4 = _T[0:256], _T[256:512], _T[512:768], _T[768:1024]


def _pass(a: int, b: int, c: int, x: list[int], mul: int) -> tuple[int, int, int]:
    """One pass: eight rounds, the three state words rotating one place per round."""
    t1, t2, t3, t4, m = _T1, _T2, _T3, _T4, _MASK
    for i in range(8):
        c ^= x[i]
        a = (a - (t1[c & 0xff] ^ t2[(c >> 16) & 0xff]
                  ^ t3[(c >> 32) & 0xff] ^ t4[(c >> 48) & 0xff])) & m
        b = (b + (t4[(c >> 8) & 0xff] ^ t3[(c >> 24) & 0xff]
                  ^ t2[(c >> 40) & 0xff] ^ t1[(c >> 56) & 0xff])) & m
        b = (b * mul) & m
        a, b, c = b, c, a
    return b, c, a


def _schedule(x: list[int]) -> None:
    m = _MASK
    x[0] = (x[0] - (x[7] ^ 0xA5A5A5A5A5A5A5A5)) & m
    x[1] ^= x[0]
    x[2] = (x[2] + x[1]) & m
    x[3] = (x[3] - (x[2] ^ (((~x[1]) & m) << 19) & m)) & m
    x[4] ^= x[3]
    x[5] = (x[5] + x[4]) & m
    x[6] = (x[6] - (x[5] ^ (((~x[4]) & m) >> 23))) & m
    x[7] ^= x[6]
    x[0] = (x[0] + x[7]) & m
    x[1] = (x[1] - (x[0] ^ (((~x[7]) & m) << 19) & m)) & m
    x[2] ^= x[1]
    x[3] = (x[3] + x[2]) & m
    x[4] = (x[4] - (x[3] ^ (((~x[2]) & m) >> 23))) & m
    x[5] ^= x[4]
    x[6] = (x[6] + x[5]) & m
    x[7] = (x[7] - (x[6] ^ 0x0123456789ABCDEF)) & m


def _compress(a: int, b: int, c: int, block: bytes) -> tuple[int, int, int]:
    x = list(struct.unpack("<8Q", block))
    aa, bb, cc = a, b, c
    a, b, c = _pass(a, b, c, x, 5)
    _schedule(x)
    c, a, b = _pass(c, a, b, x, 7)
    _schedule(x)
    b, c, a = _pass(b, c, a, x, 9)
    return a ^ aa, (b - bb) & _MASK, (c + cc) & _MASK


def tiger192(data: bytes) -> bytes:
    """The 24-byte Tiger/192 digest of `data` (original padding)."""
    a, b, c = 0x0123456789ABCDEF, 0xFEDCBA9876543210, 0xF096A5B4C3B2E187
    padded = data + b"\x01"
    padded += b"\x00" * ((56 - len(padded)) % 64)
    padded += struct.pack("<Q", len(data) * 8)
    for off in range(0, len(padded), 64):
        a, b, c = _compress(a, b, c, padded[off:off + 64])
    return struct.pack("<3Q", a, b, c)


TIGER_EMPTY = "3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3"

if tiger192(b"").hex() != TIGER_EMPTY:
    raise ImportError("tiger.py: the empty-string digest is wrong -- the "
                      "S-box table or the round function is damaged")


if __name__ == "__main__":
    import sys
    for arg in sys.argv[1:] or [""]:
        print(tiger192(arg.encode()).hex(), repr(arg))
