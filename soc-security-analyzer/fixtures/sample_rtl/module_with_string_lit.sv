module module_with_string_lit (
    input clk
);
    initial begin
        $display("This is a string literal containing // and /* which must not be stripped");
    end
endmodule
