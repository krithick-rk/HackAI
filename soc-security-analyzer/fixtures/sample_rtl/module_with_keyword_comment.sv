module module_with_keyword_comment (
    input clk,
    input rst_n,
    input [31:0] key_data, // Contains security keyword "key"
    output reg key_ready
);
    // This comment contains "secret" and should be preserved.
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            key_ready <= 1'b0;
        end else begin
            key_ready <= (key_data != 32'h0);
        end
    end
endmodule
