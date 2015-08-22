require_relative 'main'
require 'test/unit'

class TestMain < Test::Unit::TestCase

	def test_change_curve
		assert_equal([13, 17], Main.new.change_curve(3, 7, 0, 11, 13, 17))
	end

	def test_inv
		assert_equal(6, Main.new.inv(5, 29))
	end

	def test_isinf
		assert_equal(true, Main.new.isinf([0, 0]))
		assert_not_equal(true, Main.new.isinf([0, 1]))
	end

	def test_to_jacobian
		assert_equal([5, 29, 1], Main.new.to_jacobian([5, 29]))
		assert_equal(Main::G << 1, Main.new.to_jacobian(Main::G))
		#assert_equal(Main::G << 1, Main.new.to_jacobian(Main::G << 1))
	end

	def test_jacobian_double
		assert_equal([0, 0, 0], Main.new.jacobian_double([3]))
		assert_equal([56576513649176532955305617254616790498672209379484940581393603843805619269570, 39155707150128334349216371677407456506802956851096117747929288260567018884059, 65341020041517633956166170261014086368942546761318486551877808671514674964848], Main.new.jacobian_double(Main.new.to_jacobian(Main::G)))
	end

	def test_jacobian_add
		assert_equal(Main::G, Main.new.jacobian_add([0], Main::G))
		assert_equal(Main::G, Main.new.jacobian_add(Main::G, [0]))
		assert_equal(Main.new.jacobian_double(Main.new.to_jacobian(Main::G)), Main.new.jacobian_add(Main.new.to_jacobian(Main::G), Main.new.to_jacobian(Main::G)))
	end

	def test_from_jacobian
		assert_equal(Main::G, Main.new.from_jacobian(Main.new.to_jacobian(Main::G)))
	end

	def test_jacobian_multiply
		assert_equal([0, 0, 1], Main.new.jacobian_multiply([100, 0], [3]))
		assert_equal([100, 50], Main.new.jacobian_multiply([100, 50], 1))
	end

	def test_fast_add
		assert_equal(Main.new.from_jacobian(Main.new.jacobian_double(Main.new.to_jacobian(Main::G))), Main.new.fast_add(Main::G, Main::G))
	end

	def test_fast_multiply
		assert_equal(Main.new.fast_multiply(Main.new.fast_multiply(Main::G, 20), 30), Main.new.fast_multiply(Main.new.fast_multiply(Main::G, 30), 20))
	end
end