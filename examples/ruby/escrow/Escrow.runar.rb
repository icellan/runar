require 'runar'

class Escrow < Runar::SmartContract
  prop :buyer, PubKey
  prop :seller, PubKey
  prop :arbiter, PubKey

  def initialize(buyer, seller, arbiter)
    super(buyer, seller, arbiter)
    @buyer = buyer
    @seller = seller
    @arbiter = arbiter
  end

  runar_public seller_sig: Sig, arbiter_sig: Sig
  def release(seller_sig, arbiter_sig)
    assert check_sig(seller_sig, @seller)
    assert check_sig(arbiter_sig, @arbiter)
  end

  runar_public buyer_sig: Sig, arbiter_sig: Sig
  def refund(buyer_sig, arbiter_sig)
    assert check_sig(buyer_sig, @buyer)
    assert check_sig(arbiter_sig, @arbiter)
  end
end
