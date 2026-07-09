module module_with_no_keyword_comment (
    input clk,
    output reg out
);
    /* 
       This is a block comment
       without any security-relevant keywords.
       It should be fully stripped by the comment stripper
       while preserving all line numbers.
    */
    always @(posedge clk) begin
        out <= 1'b1;
    end
endmodule
