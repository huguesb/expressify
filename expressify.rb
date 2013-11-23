# Copyright (c) 2013, Hugues Bruant <hugues@bruant.info>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright notice,
#      this list of conditions and the following disclaimer.
#
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

require 'strscan'

#
# Expressify provides:
#    * Expressify::Expr : a simple class that encapsulates a safe yet powerful
#      expression evalutor that accepts a large subset of Ruby expressions
#    * Tags::* : a couple of Liquid tags and blocks that bring that power to
#      Liquid templates
#
# Liquid tags are auto-registered if Liquid is imported before Expressify.
#
module Expressify
    class EvalException < Exception
        def initialize(str, pos, msg)
            super("%s\n%s\n%s^" % [msg, str, " " * pos])
        end
    end

    #
    # Evaluate a large but safe subset of Ruby expressions
    #
    class Expr
        def initialize(str, liquid_compat = true)
            @str = str
            @liquid_compat = liquid_compat
        end

        #
        # Evaluate the expression
        #
        # context:       variable resolver, MUST implement []
        #
        # return the value of the evaluated expression or throw an exception
        #
        # This method is reentrant
        #
        def evaluate(context = nil)
            ss = StringScanner.new(@str)
            r = eval_expr(ss, context)
            peek(ss)
            error(ss.pos, "Unexpected trail") unless ss.eos?
            r
        end

        #
        # Evaluate a whitspace-separated list of expressions
        #
        # context:       variable resolver, MUST implement []
        #
        # return the sequence of evaluated values or throw an exception
        #
        # This method is reentrant
        #
        def evaluate_list(context = nil)
            ss = StringScanner.new(@str)
            r = []
            while not ss.eos?
                r << eval_expr(ss, context)
            end
            r
        end

        #
        # Method whitelisting
        #
        # cls:           Class of the object on which a method call is requested
        # method:        name of method to be called
        #
        # return whether the method call should be allowed
        #
        # The default implementation withelists a number of side-effect-free
        # methods of Ruby Core types, regardless of the value of the cls param
        #
        def whitelisted?(cls, method)
            WHITELIST.has_key?(method)
        end


    private

        def error(pos, msg, *args)
            raise EvalException.new(@str, pos, msg % args)
        end

        SPECIAL_LITERALS = {
            'nil' => nil,
            'true' => true,
            'false'=> false
        }

        ESCAPE_CHARS = {
            't' => "\t",
            'n' => "\n",
            'r' => "\r",
            'a' => "\a",
            'b' => "\b",
            's' => "\s"
        }

        #
        # A whitelist of side-effect-free methods that take no parameters
        #
        # NB: this list is based on Ruby core types. These methods may not be
        # safe for some exotic custom objects...
        #
        # Ruby 2.0 introduces the Set class in the core but to be compatible
        # with 1.9 we use a hash instead
        #
        WHITELIST = Hash[ %w[
                abs
                bytes
                capitalize ceil chars chop codepoints compact
                downcase drop
                first flatten floor
                hex
                intern invert
                keys
                last length lstrip
                next
                oct ord
                reverse rotate rstrip
                size slice sort strip succ swapcase
                to_a to_c to_f to_h to_i to_r to_s to_sym transpose truncate
                uniq upcase
                values
            ].map { |k| [k, k] }
        ]

        # for the unfortunate cases where the operator token differs from the
        # internal Ruby symbol
        class OpToken < String
            def initialize(token, sym)
                super(token)
                @sym = sym.to_sym
            end

            def to_sym
                @sym
            end
        end


        #
        # sub-expression evaluation: unfazed by trailing characters
        #
        def eval_expr(ss, context)
            eval_ternary(ss, context)
        end

        def eval_ternary(ss, context)
            x = eval_range(ss, context)

            if peek(ss) == '?'
                consume(ss, 1)
                y = eval_expr(ss, context)
                expect(ss, ':')
                z = eval_expr(ss, context)

                x ? y : z
            else
                x
            end
        end

        def eval_range(ss, context)
            x = eval_logical_or(ss, context)
            case c = read_any(ss, %w[... ..])
            when nil
                x
            else
                y = eval_logical_or(ss, context)
                Range.new(x, y, c == '...')
            end
        end

        def eval_logical_or(ss, context)
            eval_binary_associative(ss, context, :eval_logical_and,
                                    [OpToken.new("||", "|")]) # weird
        end

        def eval_logical_and(ss, context)
            eval_binary_associative(ss, context, :eval_equality,
                                    [OpToken.new("&&", "&")]) # weird
        end

        def eval_equality(ss, context)
            eval_binary(ss, context, :eval_inequality, %w[<=> == === !=])
        end

        def eval_inequality(ss, context)
            eval_binary(ss, context, :eval_bitwise_or, %w[> >= < <=])
        end

        def eval_bitwise_or(ss, context)
            eval_binary_associative(ss, context, :eval_bitwise_and, %w[| ^])
        end

        def eval_bitwise_and(ss, context)
            eval_binary_associative(ss, context, :eval_shift, %w[&])
        end

        def eval_shift(ss, context)
            eval_binary(ss, context, :eval_additive, %w[<< >>])
        end

        def eval_additive(ss, context)
            eval_binary_associative(ss, context, :eval_multiplicative, %w[+ -])
        end

        def eval_multiplicative(ss, context)
            eval_binary_associative(ss, context, :eval_unary_minus, %w[* / %])
        end

        def eval_unary_minus(ss, context)
            eval_unary(ss, context, :eval_pow, [OpToken.new("-", "-@"),
                                                OpToken.new("+", "+@")])
        end

        def eval_pow(ss, context)
            eval_binary(ss, context, :eval_not, %w[**])
        end

        def eval_not(ss, context)
            eval_unary(ss, context, :eval_deref, %w[! ~])
        end

        def eval_deref(ss, context)
            x = eval_literal(ss, context)
            until (c = read_any(ss, ['.', '['])) == nil
                p = ss.pos - 1
                case c
                when '.'
                    error(p, "left operand nil") if x == nil
                    y = eval_identifier(ss)
                    error(p, "right operand nil or empty") if y == nil or y.empty?

                    if peek(ss, 1) == '('
                        consume(ss, 1)
                        a = eval_csv(ss, context)
                        expect(ss, ')')
                        x = eval_method(p, x, y, *a)
                    else
                        r = resolve_key(x, y) if @liquid_compat
                        x = r != nil ? r : eval_method(p, x, y)
                    end
                when '['
                    y = eval_expr(ss, context)
                    expect(ss, ']')
                    x = x[y]
                end
            end
            x
        end

        def eval_method(p, x, y, *args)
            unless x.respond_to?(y) && whitelisted?(x.class, y)
                error(p, "no %s method for %s", y, x.class)
            end
            x.send(y, *args)
        end

        def resolve_key(x, y)
            if x.respond_to?(:[]) and
                    ((x.respond_to?(:has_key?) and x.has_key?(y)) or
                     (x.respond_to?(:fetch) and y.is_a?(Integer)))
                x[y]
            else
                nil
            end
        end


        def eval_literal(ss, context)
            c = read(ss)
            case c
            when '('
                x = eval_expr(ss, context)
                expect(ss, ')')
                x
            when '['
                eval_array_literal(ss, context)
            when '{'
                eval_hash_literal(ss, context)
            when '"', "'"
                eval_string_literal(ss, c)
            when ':'
                eval_identifier(ss).to_sym
            when nil
                error(ss.pos, "expected literal")
            else
                error(ss.pos - 1, "expected literal") unless /\w/ =~ c

                x = c + ss.scan(/\w+/).to_s

                if SPECIAL_LITERALS.has_key?(x)
                    SPECIAL_LITERALS[x]
                elsif /\d/ =~ c
                    # TODO: support floats as well
                    Integer(x)
                else
                    # resolve context variable
                    context[x]
                end
            end
        end

        #
        # Evaluate an array literal
        #
        # ss:       string scanner
        # context:  Liquid context
        #
        def eval_array_literal(ss, context)
            x = peek(ss, 1) == ']' ? [] : eval_csv(ss, context)
            expect(ss, ']')
            x
        end

        def eval_csv(ss, context)
            x = []
            while not ss.eos?
                x << eval_expr(ss, context)
                break if peek(ss, 1) != ','
                consume(ss, 1)
            end
            x
        end

        #
        # Evaluate a hash literal
        #
        # ss:       string scanner
        # context:  Liquid context
        #
        def eval_hash_literal(ss, context)
            x = {}
            if peek(ss, 1) == '}'
                consume(ss, 1)
                return {}
            end
            while not ss.eos?
                k = eval_hash_key(ss)
                v = eval_expr(ss, context)
                x[k] = v

                c = read(ss)
                case c
                when '}'
                    return x
                when ','
                    next
                when nil
                    break
                end
            end
            error(ss.pos, "expected '}'")
        end

        def eval_hash_key(ss)
            case c = read(ss)
            when '"', "'"
                k = eval_string_literal(ss, c)
                expect(ss, '=>')
            when ':'
                k = eval_identifier(ss).to_sym
                expect(ss, '=>')
            else
                k = (c + eval_identifier(ss)).to_sym
                expect(ss, ':')
            end
            k
        end

        #
        # Scan an identifier
        #
        # ss:       string scanner
        #
        def eval_identifier(ss)
            ss.scan(/\w+/).to_s
        end

        #
        # Evaluate a string literal (w/ scanner past opening quote)
        #
        # ss:       string scanner
        # tc:       expected terminating character
        #
        def eval_string_literal(ss, tc)
            x = ""
            while not ss.eos?
                case c = ss.getch
                when tc
                    break
                when '\\'
                    x << (tc == "'" ? unescape_quote(ss) : unescape(ss))
                else
                    x << c
                end
            end
            error(ss.pos, "expected %s", tc) if c != tc
            x
        end

        def unescape_quote(ss)
            case c = ss.getch
            when '"', "'"
                c
            else
                "\\" + c
            end
        end

        def unescape(ss)
            c = ss.getch
            ESCAPE_CHARS.has_key?(c) ? ESCAPE_CHARS[c] : c
        end

        #
        # Core binary operator evaluator (non-associative)
        #
        # ss:       string scanner
        # context:  Liquid context
        # e:        symbol of evaluator for operator of higher precedence
        # ops:      List of operators having the same precedence (as strings
        #           to be recognized)
        #
        # If either operand is null, an exception is thrown
        #
        # NB: This method relies on the matched operator tokens being identical
        # to the Ruby symbol of the corresponding operator
        #
        def eval_binary(ss, context, e, ops)
            x = send(e, ss, context)
            op = read_any(ss, ops)
            op == nil ? x : eval_binary_helper(ss, context, x, op, e)
        end

        #
        # Core binary operator evaluator (associative)
        #
        # ss:       string scanner
        # context:  Liquid context
        # e:        symbol of evaluator for operator of higher precedence
        # ops:      List of operators having the same precedence (as strings
        #           to be recognized)
        #
        # If either operand is null, an exception is thrown
        #
        # NB: This method relies on the matched operator tokens being identical
        # to the Ruby symbol of the corresponding operator
        #
        def eval_binary_associative(ss, context, e, ops)
            x = send(e, ss, context)
            until (op = read_any(ss, ops)) == nil
                x = eval_binary_helper(ss, context, x, op, e)
            end
            x
        end


        def eval_binary_helper(ss, context, x, op, e)
            p = ss.pos
            y = send(e, ss, context)
            error(p - op.length, "left operand of %s is null", op) if x == nil
            error(p - op.length, "right operand of %s is null", op) if y == nil
            x.send(op.to_sym, y)
        end

        #
        # Core unary operator evaluator
        #
        # ss:       string scanner
        # context:  Liquid context
        # e:        symbol of evaluator for operator of higher precedence
        # ops:      List of operators having the same precedence (as strings
        #           to be recognized)
        #
        # If the operand is null, an exception is thrown
        #
        # NB: This method relies on the matched operator tokens being identical
        # to the Ruby symbol of the corresponding operator
        #
        def eval_unary(ss, context, e, ops)
            op = read_any(ss, ops)
            p = ss.pos
            x = send(e, ss, context)
            if op != nil
                error(p - op.length, "operand of %s is null", op) if x == nil
                x.send(op.to_sym)
            else
                x
            end
        end

        #
        # Try to read any operator in a given set
        #
        # ss:       string scanner
        # tokens:   list of tokens to be matched (plain strings)
        #
        # return:   first match, or nil if no match
        #
        def read_any(ss, tokens)
            op = read_op(ss)
            return nil if op == nil
            # to handle OpToken properly, must return the actual token instead
            # of the matche string
            i = tokens.index op
            return tokens.at(i) if i != nil
            # rewind scan pointer if the matched token is not acceptable
            ss.pos = ss.pos - op.length
            nil
        end

        #
        # Either match (and consume) the given token or throw an exception
        #
        def expect(ss, tok)
            s = peek(ss, tok.length)
            error(ss.pos, "expected %s", tok) unless s == tok
            consume(ss, tok.length)
        end

        #
        # Build a regexp matching any of the strings in the input array
        #
        def self.rx_any(tokens)
            Regexp.new(tokens.map {|x| Regexp.escape(x)}.join('|'))
        end

        MULTICHAR_OP = Hash[
            %w[
                **
                << >>
                <= >= == != =~ !~ <=> ===
                || &&
                .. ...
            ].map { |k| [k, k] }
        ]

        #
        # Read either a multichar operators or a single non-whitespace char
        # TODO: use a DFA because performace except Ruby
        #
        def read_op(ss)
            ss.skip(/\s+/)
            n = 1
            n = n + 1 while ss.rest_size > n and MULTICHAR_OP.member? ss.peek(n + 1)
            op = ss.peek(n)
            consume(ss, n)
            op.empty? ? nil : op
        end

        #
        # Consume (aka skip) a given number of input characters
        #
        def consume(ss, n)
            (1..n).each { |i| ss.getch }
        end

        #
        # Move scanner past the next non-whitespace character and return it
        #
        def read(ss)
            ss.skip(/\s+/)
            ss.getch
        end

        #
        # Move scanner to next non-whitespace character and return it
        #
        def peek(ss, len = 1)
            ss.skip(/\s+/)
            ss.peek(len)
        end
    end

    #
    # Integration into Liquid
    #
    if Object.const_defined? "Liquid"
        module Tags
            #
            # {% expr %} tag : powerful, yet safe, expression evaluation
            #
            # This tag aims to offer an alternative to the awkward chaining of
            # syntactically-challenged filters. The tag accepts a large subset
            # of Ruby expressions:
            #     * full set of operators (unary, binary, ternary) is supported
            #       with correct precedence and associativity
            #     * Integer, String, Symbol, Array and Hash literals
            #     * large whitelist of methods for Core types (no params and
            #       no side-effects)
            #     * access to all variables accessible in a Liquid context
            #     * Liquid-like permissive syntax: a.b -> a['b']
            #
            # For instance, the following vanilla Liquid:
            #
            # {% capture tmp %}{{ page.index | minus :1 }}{% endcapture %}
            # {{ articles.sections[tmp].url }}
            #
            # can be rewritten as:
            #
            # {% expr article.sections[page.index - 1].url %}
            #
            class ExprTag < Liquid::Tag
                def render(context)
                    Expr.new(@markup).evaluate(context)
                end
            end

            #
            # {% expr %}-powered {% if %} block
            #
            # This block is a drop-in replacement for the builtin {% if %} block
            # that leverages the expression evaluator used by the {% expr %} tag
            #
            class IfExprBlock < Liquid::Block
                def initialize(tag, markup, tokens)
                    @blocks = []
                    push_block('if', markup)
                    super
                end

                def unknown_tag(tag, markup, tokens)
                    if ['elsif', 'else'].include?(tag)
                        push_block(tag, markup)
                    else
                        super
                    end
                end

                def render(context)
                    context.stack do
                        @blocks.each do |block|
                            if block[:cond].evaluate(context)
                                return render_all(block[:data], context)
                            end
                        end
                        ''
                    end
                end

                def push_block(tag, markup)
                    @blocks << {
                        cond: Expr.new(tag == 'else' ? "true" : markup),
                        data: @nodelist = []
                    }
                end
            end

            #
            # A {% raw %}-like block, {% expr %}-evaluated
            #
            # Useful for complex expressions whose readability benefits from a
            # multi-line layout.
            #
            # For instance:
            #
            # {% mexpr %}
            # [
            #      foo,
            #      bar,
            #      baz
            # ].sort.reverse
            # {% endmexpr %}
            #
            class ExprBlock < Liquid::Block
                def initialize(tag, markup, token)
                    super
                    @sep_expr = markup.strip
                end

                def parse(tokens)
                    @nodelist = []
                    @nodelist.clear
                    @str = ""
                    while token = tokens.shift
                        if token =~ /\{\%\s*#{block_delimiter}\s*\%\}/
                            end_tag
                            break
                        end
                        @str << token + " " if not token.empty?
                    end
                end

                def render(context)
                    sep = @sep_expr.empty? ?
                            "\n" :
                            Expr.new(@sep_expr).evaluate(context)
                    Expr.new(@str).evaluate_list(context).join(sep)
                end
            end
        end

        #
        # Register Liquid tags
        #
        def self.register_liquid
            Liquid::Template.register_tag('expr', Expressify::Tags::ExprTag)
            Liquid::Template.register_tag('mexpr', Expressify::Tags::ExprBlock)
            Liquid::Template.register_tag('if', Expressify::Tags::IfExprBlock)
        end
    end
end


#
# Only auto-register if Liquid is around
#
# This allows use of Expressify::Expr independently of Jekyll/Liquid
#
if Object.const_defined? "Liquid"
    Expressify.register_liquid
end
