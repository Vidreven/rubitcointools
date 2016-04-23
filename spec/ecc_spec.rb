require 'ecc'
require 'specials'

describe ECC do

	e = ECC.new

	context "#inv" do

		context "given a number in a filed" do

			it "computes a modular inverse" do
				inverse = e.inv(5, 29)
				expect(inverse).to eql 6
			end
		end

		context "given zero" do

			it "returns zero" do
				inverse = e.inv(0, 29)
				expect(inverse).to eql 0
			end
		end
	end

	context "#reject?" do

		context "given a point on a curve" do

			it "checks it's coordinates" do
				result = e.reject? [0, 0]
				expect(result).to be true
			end

			it "checks for improper coordinates" do
				result = e.reject? [0, 1]
				expect(result).to be false
			end
		end
	end

	context "#to_jacobian" do

		context "given a point on a curve" do

			it "returns it in jacobian form" do
				result = e.to_jacobian ECC::G
				expect(result).to eql [ECC::Gx, ECC::Gy, 1]
			end
		end
	end

	context "#from_jacobian" do

		context "given a point in jacobian form" do

			it "returns it's coordinates" do
				point = e.from_jacobian [ECC::Gx, ECC::Gy, 1]
				expect(point).to eql ECC::G
			end
		end
	end

	context "#pow" do

		context "given base and exponent" do

			base = 56576513649176532955305617254616790498672209379484940581393603843805619269570
			exp = 2**256 - 2**32 - 977
			res = e.pow(base, (exp+1)/4, exp)

			it "does modular exponentiation" do
				expect(res.class).to be Bignum
			end

			it "returns proper result" do
				expect(res).to be < exp
			end
		end
	end

	context "#legendre" do

		context "given number and modulus" do

			p = 7

			it "checks if number is quadratic residue for modulus" do
				a = 4
				result = e.legendre(a, p)
				expect(result).to eql 1
			end

			it "checks is number is quadratic non-residue for modulus" do
				b = 3
				result = e.legendre(b, p)
				expect(result).to eql -1
			end

			it "checks if number divides modulus" do
				result = e.legendre(p, p)
				expect(result).to eql 0
			end
		end
	end

	context "#on_curve?" do

		context "given an invalid point" do

			it "checks that point is not on curve" do
				result = e.on_curve? [0, 0]
				expect(result).to be false
			end
		end

		context "given a valid point" do

			it "confirms it's on curve" do
				result = e.on_curve? ECC::G
				expect(result).to eql true
			end
		end
	end

	context "#get_y" do

		context "given x-coordinate" do

			it "calculates y-coordinate" do
				x = 0
				y = e.get_y x
				expect(e.on_curve? [x, y]).to be false
			end

			it "calculates valid y-coordinate" do
				x = 1
				y = e.get_y x
				expect(e.on_curve? [x, y]).to be true
			end
		end
	end

	context "#format_point" do

		context "given x-coordinate outside Fp" do
			it "adds P to it" do
				point = e.format_point [-3]
				expect(e.on_curve? point).to be true
			end

			it "subtracts P from it" do
				point = e.format_point [2 * ECC::P + 1]
				expect(e.on_curve? point).to be true
			end
		end

		context "given x-coordinate" do

			it "calculates y-coordinate, converts to jacobian" do
				point = e.format_point [ECC::Gx]
				expect(point[2]).to eql 1 
			end
		end

		context "given a point" do

			it "converts to jacobian" do
				point = e.format_point ECC::G
				expect(point[2]).to eql 1
			end
		end
	end

	context "#jacobian_double" do

		context "given only x-coordinate" do

			it "gets y-coordinate, converts to jacobian, doubles it" do
				point = e.jacobian_double [ECC::Gx]
				point = e.from_jacobian point
				expect(e.on_curve? point).to eql true
			end
		end

		context "given a point in non-jacobian form" do

			it "converts it to jacobian & doubles it" do
				point = e.jacobian_double ECC::G
				point = e.from_jacobian point
				expect(e.on_curve? point).to eql true
			end
		end

		context "given a point in jacobian form" do

			it "doubles it" do
				point = e.to_jacobian ECC::G
				point = e.jacobian_double point
				point = e.from_jacobian point
				expect(e.on_curve? point).to eql true
			end
		end

		context "given point at infinity" do

			it "returns point" do
				point = e.jacobian_double ECC::O
				expect(point).to eql ECC::O
			end
		end
	end

	context "#jacobian_add" do

		context "given two points" do

			it "adds them" do
				point = [ECC::Gx, ECC::Gy, 1]
				double = e.jacobian_add(point, point)
				expect(double).to eql e.jacobian_double point
			end
		end

		context "given identity element" do

			it "returns identity" do
				result = e.jacobian_add(ECC::O, ECC::G)
				expect(result).to eql ECC::G
			end
		end
	end

	context "#jacobian_multiply" do

		context "given an invalid point" do

			it "returns zero" do
				point = [1, 0, 1]
				n = 2
				result = e.jacobian_multiply(point, n)
				expect(result).to eql [0, 0, 1]
			end
		end

		context "given an invalid multiplier" do

			it "returns zero" do
				point = [1, e.get_y(1), 1]
				n = 0
				result = e.jacobian_multiply(point, n)
				expect(result).to eql [0, 0, 1]
			end
		end

		context "given valid point and multiplier" do

			it "multiplies the point with multiplier" do
				point = [1, e.get_y(1), 1]
				n = 2
				result = e.jacobian_multiply(point, n)
				expect(result).to eql e.jacobian_double point
			end
		end
	end

	context "#fast_add" do

		context "given two points on curve" do

			it "adds them" do
				result = e.fast_add(ECC::G, ECC::G)
				double = e.from_jacobian(e.jacobian_double(e.to_jacobian(ECC::G)))
				expect(result).to eql double
			end
		end
	end

	context "#fast_multiply" do

		context "given a point on curve" do

			it "multiplies it given number of times" do
				left = e.fast_multiply(e.fast_multiply(ECC::G, 2), 3)
				right = e.fast_multiply(e.fast_multiply(ECC::G, 3), 2)
				expect(left).to eql right
			end
		end
	end
end