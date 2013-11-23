
require "./expressify"
require "test/unit"

module Expressify

    class TestExpr < Test::Unit::TestCase
        def assert_expr(expected, expr, cxt = nil)
            begin
                assert_equal(expected, Expr.new(expr).evaluate(cxt),
                             "%s =/=> %s" % [expr, expected.to_s])
            rescue EvalException => e
                assert(false, e.message)
                raise
            end
        end

        def test_special_literal
            assert_expr(nil, "nil")
            assert_expr(true, "true")
            assert_expr(false, "false")
        end

        def test_int_literal
            assert_expr(0, "0")
            assert_expr(-1, "-1")
            assert_expr(42, "42")
        end

        def test_string_literal
            assert_expr('foo', %q['foo'])
            assert_expr("bar", %q["bar"])
            assert_expr('f\'o', %q['f\'o'])
            assert_expr("f\'o", %q["f\'o"])
            assert_expr('\b\a\r', %q['\b\a\r'])
            assert_expr("\b\a\r", %q["\b\a\r"])
        end

        def test_sym_literal
            assert_expr(:foo, ":foo")
        end

        def test_range_literal
            assert_expr(1..42, "1..42")
            assert_expr(0...2, "0...2")
        end

        def test_array_literal
            assert_expr([], "[]")
            assert_expr([1], "[1]")
            assert_expr([2, -3, "foo"], '[2,-3, "foo"]')
        end


        def test_hash_literal
            assert_expr({}, "{}")
            assert_expr({a: 1}, "{a: 1}")
            assert_expr({:a => []}, "{:a => []}")
            assert_expr({'a' => {}}, "{'a' => {}}")
        end

        def test_var_literal
            cxt = { 'foo' => 'bar' }
            assert_expr(cxt['foo'], "foo", cxt)
        end

        def test_binary_op
            assert_expr(2 + 3, "2 + 3")
            assert_expr(2 - 3, "2 - 3")
            assert_expr(2 * 3, "2 * 3")
            assert_expr(2 / 3, "2 / 3")
            assert_expr(2 % 3, "2 % 3")
            assert_expr(2 ** 3, "2 ** 3")
            assert_expr(2 & 3, "2 & 3")
            assert_expr(2 ^ 3, "2 ^ 3")
            assert_expr(2 | 3, "2 | 3")
            assert_expr(2 << 3, "2 << 3")
            assert_expr(2 >> 3, "2 >> 3")
            assert_expr(2 == 3, "2 == 3")
            assert_expr(2 != 3, "2 != 3")
            assert_expr(2 <=> 3, "2 <=> 3")
            assert_expr(2 === 3, "2 === 3")
            assert_expr(2 <= 3, "2 <= 3")
            assert_expr(2 >= 3, "2 >= 3")
            assert_expr(2 < 3, "2 < 3")
            assert_expr(2 > 3, "2 > 3")
            assert_expr(true || false, "true || false")
            assert_expr(true || true, "true || true")
            assert_expr(true && false, "true && false")
            assert_expr(true && true, "true && true")
            assert_expr("foo" == "bar", '"foo" == "bar"')
        end

        def test_assoc
            assert_expr(2 + 3 + 4 + 5 + 6, "2 + 3 + 4 + 5 + 6")
            assert_expr(2 - 3 + 4 - 5 + 6, "2 - 3 + 4 - 5 + 6")
            assert_expr(2 * 3 * 4 * 5 * 6, "2 * 3 * 4 * 5 * 6")
            assert_expr(2 * 3 / 4 * 5 / 6, "2 * 3 / 4 * 5 / 6")
        end

        def test_precedence
            assert_expr(2 + 3 * 4 - 5 / 6, "2 + 3 * 4 - 5 / 6")
            assert_expr(2 < 3 || 4 > 5, "2 < 3 || 4 > 5")
        end

        def test_array
            assert_expr(['a', 2, 1..4][0], "['a', 2, 1..4][0]")
            assert_expr(['a'] + [2, 1..4], "['a'] + [2, 1..4]")
        end

        def test_hash
            assert_expr({'a' => 1..4}['a'], "{'a' => 1..4}['a']")
        end

        def test_liquid_shorthand
            assert_expr("b", "{'a' => 'b'}.a")
        end

        def assert_error(expr, cxt = nil)
            begin
                Expr.new(expr).evaluate(cxt)
                assert(false, "accepted invalid expression: %s" % expr)
            rescue EvalException => e
                puts "#{e.message}"
                assert(true, e.message)
            end
        end

        def test_errors
            assert_error("-")
            assert_error("* 0")
            assert_error("42 <<")
            assert_error("nil + 0")
            assert_error('"foo" == nil')
        end
    end
end
