module module_with_inline_code_comment (
    input clk,
    output reg [7:0] val
);
    always @(posedge clk) begin
        val <= 8'hAA; // secret path keyword
    end
endmodule
