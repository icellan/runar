package runar.compiler.ir.anf;

import java.util.List;

public record AnfMethod(String name, List<AnfParam> params, List<AnfBinding> body, boolean isPublic) {}
