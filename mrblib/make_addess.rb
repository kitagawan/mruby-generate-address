class Generate_Address
 def initialize
  #乱数(Root Seed)
  root_seed=SecureRandom.hex(16)
  #secp256k1の曲線パラメータ
  #基準点G(x,y)
  #x座標
  @g_x="0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798".to_i(16)
  #y座標
  @g_y="0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8".to_i(16)
  #剰余の素数
  @prime="0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F".to_i(16)
  data=[root_seed].pack("H*")
  key='Bitcoin seed'
  l=Digest::HMAC.digest(data,key,Digest::SHA512)
  #親秘密鍵の生成(Master Private Key)
  @priv_key=l[0..31].unpack("H*")[0]
  #親チェインコード
  @chain_code=l[32..-1]
  #index値
  @index=1
 end
  
  #mod空間への変換部分
  def mod(n)
    return n % @prime
  end

  #モジュラ逆数変換部分
  def inverse(m)
    remainders = [m, @prime]
    s = [1, 0]
    t = [0, 1]
    arrays = [remainders, s, t]
    while remainders.last > 0
      #ユークリッドの互除法によるモジュラ逆数導出
      #負の数の除算における商の場合分け
      if remainders[-2]<0
        quotient=-1
      else
        quotient = remainders[-2] / remainders[-1]
      end

      arrays.each do |array|
        #余りの導出
        array << array[-2] - quotient * array[-1]
      end

    end

    return mod(s[-2])
  end

  #楕円曲線の公開鍵圧縮形式(圧縮)
  def header(p) 
    if p[1]%2==0
    #偶数
    return "02"+p[0].to_s(16)
    else
    #奇数
    return "03"+p[0].to_s(16)
    end 
  end

  #公開鍵の生成
  def pub(key)
    str=key.to_s(2).split(//)
    i=1
    #上書きされる基準点用
    point_p=[@g_x,@g_y]
    #固定する基準点
    point_q=[@g_x,@g_y]
    while str[i] != nil
    #2P+P(2倍算して基準点を足す)
      if str[i]=="1"
    #2倍算
    ramda=mod(3*point_p[-2]*point_p[-2])*inverse(2*point_p[-1])
    sum_x=mod((ramda*ramda)-point_p[-2]-point_p[-2])
    sum_y=mod(ramda*(point_p[-2]-sum_x)-point_p[-1])
    point_p=[sum_x,sum_y]
    #基準点を足す
    ramda=mod(point_p[-1]-point_q[-1])*inverse(point_p[-2]-point_q[-2])
    sum_x=mod((ramda*ramda)-point_p[-2]-point_q[-2])
    sum_y=mod(ramda*(point_p[-2]-sum_x)-point_p[-1])
    point_p=[sum_x,sum_y]
    i=i+1
    #2P(2倍算)
    elsif str[i]=="0"
    ramda=mod(3*point_p[-2]*point_p[-2])*inverse(2*point_p[-1])
    sum_x=mod((ramda*ramda)-point_p[-2]-point_p[-2])
    sum_y=mod(ramda*(point_p[-2]-sum_x)-point_p[-1])
    point_p=[sum_x,sum_y]
    i=i+1
    end
  end
   return point_p
  end

  #楕円曲線上の和
  def add(point1,point2)
    point_p=point1
    point_q=point2
    if point_p[-2]==point_q[-2]
    ramda=mod(3*point_p[-2]*point_p[-2])*inverse(2*point_p[-1])
    sum_x=mod((ramda*ramda)-point_p[-2]-point_q[-2])
    sum_y=mod(ramda*(point_p[-2]-sum_x)-point_p[-1])
    point_p=[sum_x,sum_y]
    else
    ramda=mod(point_p[-1]-point_q[-1])*inverse(point_p[-2]-point_q[-2])
    sum_x=mod((ramda*ramda)-point_p[-2]-point_q[-2])
    sum_y=mod(ramda*(point_p[-2]-sum_x)-point_p[-1])
    point_p=[sum_x,sum_y]
    end
    return point_p 
  end

  #鍵の生成
  #どちらのメソッドにおいても実行結果は等しいはず
  #秘密鍵を記録しておき鍵生成を行う場合
  def genekey
  #index+秘密鍵
  data=[header(pub(@priv_key.to_i(16)))].pack("H*")
  data=data << [@index].pack('N')
  key=@chain_code
  #テスト用変数
  @p=@priv_key
  @k=@chain_code
  k_p=Digest::HMAC.digest(data,key,Digest::SHA512)
  bprive_key=@priv_key
  @priv_key=k_p[0..31].unpack("H*")[0]
  @chain_code=k_p[32..-1]
  t=bprive_key.to_i(16)+@priv_key.to_i(16)
  ch_pubkey=pub(t)
  p header(ch_pubkey)
  end

  #公開鍵を利用して階層的に鍵生成を行う場合
  def genekey2
  #親公開鍵を設定
  pubkey=pub(@p.to_i(16))
  data=[header(pubkey)].pack("H*")
  data=data << [@index].pack('N')
  k_p=Digest::HMAC.digest(data,@k,Digest::SHA512)
  priv_key=k_p[0..31].unpack("H*")[0]
  cl=pub(priv_key.to_i(16))
  ch_pubkey=add(pubkey,cl)
  p header(ch_pubkey)
  @index+=1
  end
end
