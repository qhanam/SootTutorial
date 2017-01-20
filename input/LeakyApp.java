public class LeakyApp {

	public static void main (String[] args) {
		
		LeakyApp app = new LeakyApp();
		Pair pair = new Pair();
		String data = app.source();
		pair.key = "jsmith";
		pair.value = data;
		app.sink(data);
		app.sink(pair.value);

	}

	public LeakyApp() { }

	/**
	 * return some private information.
	 */
	public String source() {
		return "private-info";
	}

	/**
	 * Sends information in a non-private manner.
	 * @param data The information to send.
	 */
	public void sink(String data) {
		System.out.println(data);
	}

}
