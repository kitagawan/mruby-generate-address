assert('Generate_Address') do
    g= Generate_Address.new
    a=g.pub("d4f5ebae05fd3ded311b55bc8fe9896467f890751a9eb6d48ad1e0d9fb1e19aa".to_i(16))
    assert_equal(g.header(a),"03cd834eefcd7c4b65569e18d3e3e35d013f717ea3ade0cae7933749fc56febfd",message="False")
  end
