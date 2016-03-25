require_relative 'ecc'
require_relative 'specials'
require 'test/unit'

class TestECC < Test::Unit::TestCase

	def test_change_curve
		e = ECC.new
		assert_equal([13, 17], e.change_curve(3, 7, 0, 11, 13, 17))
	end

	def test_inv
		e = ECC.new
		assert_equal(6, e.inv(5, 29))
	end

	def test_isinf
		e = ECC.new
		assert_equal(true, e.isinf([0, 0]))
		assert_not_equal(true, e.isinf([0, 1]))
	end

	def test_to_jacobian
		e = ECC.new
		assert_equal([5, 29, 1], e.to_jacobian([5, 29]))
		assert_equal(ECC::G << 1, e.to_jacobian(ECC::G))
	end

	def test_jacobian_double
		e = ECC.new
		assert_equal([0, 0, 0], e.jacobian_double([3]))
		assert_equal([56576513649176532955305617254616790498672209379484940581393603843805619269570, 39155707150128334349216371677407456506802956851096117747929288260567018884059, 65341020041517633956166170261014086368942546761318486551877808671514674964848], e.jacobian_double(e.to_jacobian(ECC::G)))
	end

	def test_jacobian_add
		e = ECC.new
		assert_equal(ECC::G, e.jacobian_add([0], ECC::G))
		assert_equal(ECC::G, e.jacobian_add(ECC::G, [0]))
		assert_equal(e.jacobian_double(e.to_jacobian(ECC::G)), e.jacobian_add(e.to_jacobian(ECC::G), e.to_jacobian(ECC::G)))
	end

	def test_from_jacobian
		e = ECC.new
		assert_equal(ECC::G, e.from_jacobian(e.to_jacobian(ECC::G)))
	end

	def test_jacobian_multiply
		e = ECC.new
		assert_equal([0, 0, 1], e.jacobian_multiply([100, 0], [3]))
		assert_equal([100, 50], e.jacobian_multiply([100, 50], 1))
	end

	def test_fast_add
		e = ECC.new
		assert_equal(e.from_jacobian(e.jacobian_double(e.to_jacobian(ECC::G))),e.fast_add(ECC::G, ECC::G))
	end

	def test_fast_multiply
		e = ECC.new
		assert_equal(e.fast_multiply(e.fast_multiply(ECC::G, 20), 30), e.fast_multiply(e.fast_multiply(ECC::G, 30), 20))
	end

	def test_pow
		e = ECC.new
		base = 56576513649176532955305617254616790498672209379484940581393603843805619269570
		exp = 2**256 - 2**32 - 977
		res = e.pow(base, (exp+1)/4, exp)
		assert_equal(Bignum, res.class)
	end

	def test_legendre
		e = ECC.new
		p = 7
		a = 4
		b = 3
		c = 7
		res = e.legendre(a, p)
		assert_equal(1, res)
		res = e.legendre(b, p)
		assert_equal(-1, res)
		res = e.legendre(c, p)
		assert_equal(0, res)
	end
end